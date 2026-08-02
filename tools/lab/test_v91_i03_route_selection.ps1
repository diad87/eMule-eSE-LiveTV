<#
.SYNOPSIS
Runs the normative V91-I03 route-selection campaign on two controlled Windows
hosts without changing adapters, routes, DNS, hosts files or firewall state.

.DESCRIPTION
Run one Coordinator role and one Peer role against a shared CoordinationRoot.
The coordinator creates two isolated candidate profiles and tests, in order:

  * IPv6Mode=1 (Auto): an ordinary dual-stack HighID peer must use IPv4.
  * IPv6Mode=2 (Preferred): the same peer must use IPv6.

Each client first receives an IPv4-only explicit source link.  A real IPv4
connection and OP_HelloAnswer then teach that same in-memory peer object the
peer's public IPv6 address and dual-stack capability.  The peer process is
restarted only after a two-host barrier, forcing a subsequent dial.  PASS
requires a new PID-owned Established socket on the expected family, a physical
non-virtual data interface, a matching inbound socket owned by the restarted
peer process, responsive UI/API, and NetLab/Kad/proxy/DNS/third-party-server
isolation.  Each downloader connects only to a nonce-scoped minimal eD2K
server bound to the coordinator's own physical IPv4.  That controlled server
accepts LOGINREQUEST and returns one HighID IDCHANGE solely to keep the
production download scheduler's IsConnected() precondition true.

This harness deliberately has no DNS fixture (V91-D01), no Kad/bootstrap,
no third-party source and no firewall setup. Missing direct native T1/T2
topology or ambiguous evidence is BLOCKED. A policy mismatch after a fully
valid fixture is FAIL. T1 is reported only when both physical prefixes are
equal and IPv6 is on-link; a routed native IPv6 next hop is reported as T2.
#>
[CmdletBinding()]
param(
    [ValidateSet('Coordinator', 'Peer')][string]$Role = 'Coordinator',
    [Parameter(Mandatory = $true)][string]$PackagePath,
    [Parameter(Mandatory = $true)][string]$CandidateZipPath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedCandidateZipSha256,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')][string]$Commit,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedEmuleSha256,
    [Parameter(Mandatory = $true)][string]$PeerIPv4,
    [Parameter(Mandatory = $true)][string]$PeerLocalIPv4,
    [Parameter(Mandatory = $true)][string]$PeerIPv6,
    [Parameter(Mandatory = $true)][string]$CoordinationRoot,
    [Parameter(Mandatory = $true)][switch]$ControlledPeerAcknowledged,
    [Parameter(Mandatory = $true)][switch]$DisposableLabAccountAcknowledged,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedLabUserSidSha256,
    [ValidateRange(1024, 65535)][int]$PeerTcpPort = 9462,
    [ValidateRange(1024, 65535)][int]$PeerUdpPort = 9472,
    [ValidateRange(1024, 65535)][int]$PeerWebPort = 9511,
    [ValidateRange(1024, 65535)][int]$AutoTcpPort = 9562,
    [ValidateRange(1024, 65535)][int]$AutoUdpPort = 9572,
    [ValidateRange(1024, 65535)][int]$AutoWebPort = 9611,
    [ValidateRange(1024, 65535)][int]$PreferredTcpPort = 9662,
    [ValidateRange(1024, 65535)][int]$PreferredUdpPort = 9672,
    [ValidateRange(1024, 65535)][int]$PreferredWebPort = 9711,
    [ValidateRange(268435456, 17179869184)]
    [Int64]$FileSizeBytes = 1073741824,
    [ValidateRange(30, 900)][int]$PeerReadyTimeoutSeconds = 300,
    [ValidateRange(60, 3600)][int]$CaseTimeoutSeconds = 2400,
    [ValidateRange(3, 30)][int]$StableObservationSeconds = 5,
    [ValidatePattern('^[0-9a-fA-F]{32}$')][string]$RunNonce = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'common.ps1')

$caseId = 'V91-I03'
$expectedHash = $ExpectedEmuleSha256.ToLowerInvariant()
$expectedZipHash = $ExpectedCandidateZipSha256.ToLowerInvariant()
$expectedLabSidHash = $ExpectedLabUserSidSha256.ToLowerInvariant()
$peerUploadCapKiBps = 16
$candidate = Get-LabCandidateInfo -PackagePath $PackagePath `
    -ExpectedCommit $Commit
if ($candidate.emule_sha256 -ne $expectedHash) {
    throw "Candidate hash mismatch: package=$($candidate.emule_sha256) expected=$expectedHash"
}
if (-not $ControlledPeerAcknowledged) {
    throw 'I03 requires two controlled physical Windows hosts'
}
if (-not $DisposableLabAccountAcknowledged) {
    throw 'I03_FIXTURE_BLOCKED: dedicated disposable lab account required'
}
$currentLabSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$currentLabSidHash = Get-LabStringSha256 -Value $currentLabSid
if ($currentLabSidHash -cne $expectedLabSidHash) {
    throw 'I03_FIXTURE_BLOCKED: dedicated lab account SID binding mismatch'
}
$candidateZip = Get-LabFullPath -Path $CandidateZipPath
if (-not (Test-Path -LiteralPath $candidateZip -PathType Leaf)) {
    throw 'I03_FIXTURE_BLOCKED: CandidateZipPath is missing'
}
$candidateZipSha256 = Get-LabSha256 -Path $candidateZip
if ($candidateZipSha256 -cne $expectedZipHash) {
    throw 'I03_FIXTURE_BLOCKED: candidate ZIP SHA-256 mismatch'
}
$candidatePackagePrefix =
    (Get-LabFullPath -Path $candidate.package_path).TrimEnd('\') + '\'
if (($candidateZip.TrimEnd('\') + '\').StartsWith(
        $candidatePackagePrefix,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'I03_FIXTURE_BLOCKED: CandidateZipPath must be outside PackagePath'
}
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'V91-I03 T1/T2 is a Windows-only two-host fixture'
}

function Convert-I03Address {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)]
        [Net.Sockets.AddressFamily]$Family,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Value.Split('%')[0], [ref]$parsed) -or
        $parsed.AddressFamily -ne $Family -or
        ($Family -eq [Net.Sockets.AddressFamily]::InterNetworkV6 -and
            $parsed.IsIPv4MappedToIPv6)) {
        throw "$Name is not an address in the required family: '$Value'"
    }
    return $parsed
}

function Get-I03NormalizedIp {
    param([Parameter(Mandatory = $true)][string]$Address)

    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Address.Trim('[', ']').Split('%')[0],
        [ref]$parsed)) {
        return $Address
    }
    if ($parsed.IsIPv4MappedToIPv6) {
        return $parsed.MapToIPv4().ToString()
    }
    return $parsed.ToString()
}

function Test-I03PathContainedBy {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $fullPath = (Get-LabFullPath -Path $Path).TrimEnd('\')
    $fullRoot = (Get-LabFullPath -Path $Root).TrimEnd('\')
    return $fullPath.Equals(
        $fullRoot, [StringComparison]::OrdinalIgnoreCase
    ) -or $fullPath.StartsWith(
        $fullRoot + '\', [StringComparison]::OrdinalIgnoreCase
    )
}

function Assert-I03PrivateRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$CandidatePackageRoot
    )

    $fullPath = Get-LabFullPath -Path $Path
    if (Test-I03PathContainedBy -Path $fullPath -Root $RepositoryRoot) {
        throw "I03_PRIVATE_ROOT::${Label}_INSIDE_REPOSITORY"
    }
    if (Test-I03PathContainedBy -Path $fullPath `
        -Root $CandidatePackageRoot) {
        throw "I03_PRIVATE_ROOT::${Label}_INSIDE_PACKAGE"
    }
    $cursor = $fullPath
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if (($item.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "I03_PRIVATE_ROOT::${Label}_REPARSE_ANCESTOR"
            }
        }
        $parent = Split-Path -Parent $cursor
        if (-not $parent -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
    return $fullPath
}

function Test-I03PublicEvidenceText {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()][string]$Text
    )

    $forbidden = @(
        '(?i)"(?:[a-z0-9]+_)*(?:path|address|ip|host|machine|userhash|user_hash|runtime_error|raw_error|message|password|token|cookie|authorization)(?:_[a-z0-9]+)*"\s*:',
        '(?i)"(?:[a-z0-9]+_)*(?:exception|detail|secret|auth|bearer|credential|private_key)(?:_[a-z0-9]+)*"\s*:',
        '(?i)"(?:error|[a-z0-9_]+_error)"\s*:',
        '(?i)user[_-]?hash',
        '(?i)"Bearer\s+[A-Za-z0-9._~+/=-]+"',
        '(?i)(?:System\.)?[A-Za-z0-9_.]+Exception(?::|\\r|\\n|\b)',
        '(?i)"(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{12,}|eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,})"',
        '(?i)[A-Z]:\\',
        '\\\\[^"\r\n]+\\',
        '(?<![0-9])(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}(?![0-9])',
        '(?i)(?<![0-9a-f])(?:[0-9a-f]{0,4}:){3,}[0-9a-f]{0,4}(?![0-9a-f:])',
        '(?i)BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY'
    )
    foreach ($pattern in $forbidden) {
        if ($Text -match $pattern) { return $false }
    }
    return $true
}

function Test-I03PublicEvidenceObject {
    param([Parameter(Mandatory = $true)][object]$Value)

    try {
        $text = $Value | ConvertTo-Json -Depth 32 -Compress
        if (-not (Test-I03PublicEvidenceText -Text $text) -or
            $null -eq $Value -or $Value.schema -isnot [string]) {
            return $false
        }
        $exact = {
            param([object]$Object, [string[]]$Names)
            if ($null -eq $Object) { return $false }
            $actual = @($Object.PSObject.Properties.Name)
            return $actual.Count -eq $Names.Count -and
                @($Names | Where-Object {
                    $actual -cnotcontains $_
                }).Count -eq 0
        }
        $hash = { param($v) $v -is [string] -and $v -cmatch '^[0-9a-f]{64}$' }
        $bool = { param($v) $v -is [bool] }
        $integer = {
            param($v)
            return $v -isnot [bool] -and $v -is [ValueType] -and
                $v -isnot [single] -and $v -isnot [double] -and
                $v -isnot [decimal] -and
                $v -isnot [DateTime] -and $v -isnot [char]
        }
        $nonnegative = {
            param($v)
            return (& $integer $v) -and [Int64]$v -ge 0
        }
        $positive = {
            param($v)
            return (& $integer $v) -and [Int64]$v -gt 0
        }
        $productCodes = [ordered]@{
            CANDIDATE_EXITED = 'PRODUCT_RUNTIME'
            UI_UNRESPONSIVE = 'PRODUCT_LIVENESS'
            API_UNAVAILABLE = 'PRODUCT_LIVENESS'
            API_CONTRACT = 'PRODUCT_CONTRACT'
            LINK_REJECTED = 'PRODUCT_INPUT'
            IPV4_PREWARM_INVARIANT = 'PRODUCT_ROUTE'
            PEER_IDENTITY_CHANGED = 'PRODUCT_IDENTITY'
            NO_ROUTE = 'PRODUCT_ROUTE'
            WRONG_FAMILY = 'PRODUCT_ROUTE'
            DUPLICATE_ROUTE = 'PRODUCT_ROUTE'
            WRONG_OR_NONPHYSICAL_SOCKET = 'PRODUCT_ATTRIBUTION'
            CANDIDATE_THIRD_PARTY_SOCKET = 'PRODUCT_ATTRIBUTION'
        }
        $labCodes = [ordered]@{
            PACKAGE_BINDING = 'LAB_PACKAGE'
            TOPOLOGY = 'LAB_TOPOLOGY'
            CLOCK = 'LAB_CLOCK'
            CONTROL_TIMEOUT = 'LAB_CONTROL'
            COORDINATION_SCHEMA = 'LAB_CONTROL'
            COLLECTOR_UNAVAILABLE = 'LAB_COLLECTOR'
            COLLECTOR_AMBIGUOUS = 'LAB_COLLECTOR'
            EXTERNAL_CONTAMINATION = 'LAB_CONTAMINATION'
            EVIDENCE_INCOMPLETE = 'LAB_EVIDENCE'
            CLEANUP_INCOMPLETE = 'LAB_CLEANUP'
            HARNESS_EXCEPTION = 'LAB_HARNESS'
        }
        $failurePhases = @(
            'preflight', 'dualstack_rearm', 'ipv4_prewarm',
            'peer_restart', 'peer_completion', 'cleanup',
            'case_setup', 'identity_bootstrap', 'candidate_startup',
            'link_injection', 'backlog_revalidation',
            'post_restart_route', 'evidence_finalize'
        )
        if ([string]$Value.schema -ceq
            'ese.v91.i03-public-evidence-manifest/v1') {
            $manifestFields = if ($Value.PSObject.Properties.Name `
                -ccontains 'role') {
                @(
                    'schema', 'case_id', 'role', 'files',
                    'private_artifacts_retained',
                    'private_artifact_manifest_sha256',
                    'public_scan_passed'
                )
            } else {
                @(
                    'schema', 'case_id', 'files',
                    'private_artifacts_retained',
                    'private_artifact_manifest_sha256',
                    'public_scan_passed'
                )
            }
            if (-not (& $exact $Value $manifestFields) -or
                [string]$Value.case_id -cne 'V91-I03' -or
                ($manifestFields -ccontains 'role' -and
                    [string]$Value.role -cne 'Peer') -or
                $Value.files -isnot [System.Array] -or
                @($Value.files).Count -ne 1 -or
                -not (& $bool $Value.private_artifacts_retained) -or
                -not [bool]$Value.private_artifacts_retained -or
                -not (& $bool $Value.public_scan_passed) -or
                -not [bool]$Value.public_scan_passed -or
                -not (& $hash $Value.private_artifact_manifest_sha256)) {
                return $false
            }
            $file = @($Value.files)[0]
            return (& $exact $file @('name', 'bytes', 'sha256')) -and
                [string]$file.name -ceq 'summary.json' -and
                ($file.bytes -is [int] -or $file.bytes -is [Int64]) -and
                [Int64]$file.bytes -gt 0 -and (& $hash $file.sha256)
        }
        if ([string]$Value.schema -ceq
            'ese.v91.i03-public-summary/v1') {
            if (-not (& $exact $Value @(
                'schema', 'case_id', 'formal_status', 'candidate',
                'topology', 'policies', 'adjudication', 'failures',
                'cleanup', 'retention'
            )) -or [string]$Value.case_id -cne 'V91-I03' -or
                [string]$Value.formal_status -cnotin @(
                    'PASS', 'FAIL', 'BLOCKED'
                ) -or
                -not (& $exact $Value.candidate @(
                    'commit', 'emule_sha256', 'zip_sha256',
                    'package_manifest_sha256', 'package_unchanged'
                )) -or
                [string]$Value.candidate.commit -notmatch '^[0-9a-f]{40}$' -or
                -not (& $hash $Value.candidate.emule_sha256) -or
                -not (& $hash $Value.candidate.zip_sha256) -or
                -not (& $hash $Value.candidate.package_manifest_sha256) -or
                -not (& $bool $Value.candidate.package_unchanged) -or
                -not (& $exact $Value.topology @(
                    'class', 'proved', 't1_proved', 't2_proved'
                )) -or
                [string]$Value.topology.class -cnotin @('', 'T1', 'T2') -or
                -not (& $bool $Value.topology.proved) -or
                -not (& $bool $Value.topology.t1_proved) -or
                -not (& $bool $Value.topology.t2_proved) -or
                $Value.policies -isnot [System.Array] -or
                $Value.failures -isnot [System.Array]) {
                return $false
            }
            foreach ($policy in @($Value.policies)) {
                if (-not (& $exact $policy @(
                    'policy', 'ipv6_mode', 'expected_family',
                    'fixture_valid', 'product_match'
                )) -or [string]$policy.policy -cnotin @('auto', 'preferred') -or
                    -not (& $integer $policy.ipv6_mode) -or
                    [int]$policy.ipv6_mode -notin @(1, 2) -or
                    [string]$policy.expected_family -cnotin @('IPv4', 'IPv6') -or
                    -not (& $bool $policy.fixture_valid) -or
                    -not (& $bool $policy.product_match)) { return $false }
                if (([string]$policy.policy -ceq 'auto' -and
                        ([int]$policy.ipv6_mode -ne 1 -or
                        [string]$policy.expected_family -cne 'IPv4')) -or
                    ([string]$policy.policy -ceq 'preferred' -and
                        ([int]$policy.ipv6_mode -ne 2 -or
                        [string]$policy.expected_family -cne 'IPv6'))) {
                    return $false
                }
            }
            $policyNames = @(@($Value.policies) | ForEach-Object {
                [string]$_.policy
            } | Sort-Object -Unique)
            if (@($Value.policies).Count -gt 2 -or
                $policyNames.Count -ne @($Value.policies).Count -or
                ([string]$Value.formal_status -ceq 'PASS' -and
                    ($policyNames -join '|') -cne 'auto|preferred')) {
                return $false
            }
            if (-not (& $exact $Value.adjudication @(
                'formal_status', 'proven_product_failure_count',
                'untrusted_product_failure_count', 'lab_incident_count',
                'malformed_or_stale_failure_count'
            )) -or [string]$Value.adjudication.formal_status -cne
                [string]$Value.formal_status -or
                -not (& $nonnegative `
                    $Value.adjudication.proven_product_failure_count) -or
                -not (& $nonnegative `
                    $Value.adjudication.untrusted_product_failure_count) -or
                -not (& $nonnegative `
                    $Value.adjudication.lab_incident_count) -or
                -not (& $nonnegative `
                    $Value.adjudication.malformed_or_stale_failure_count)) {
                return $false
            }
            foreach ($failure in @($Value.failures)) {
                if (-not (& $exact $failure @(
                    'role', 'policy', 'phase', 'status', 'category',
                    'code', 'fixture_certified', 'cleanup_complete',
                    'cleanup_incident_codes'
                )) -or [string]$failure.role -cnotin @('Coordinator', 'Peer') -or
                    [string]$failure.policy -cnotin @('none', 'auto', 'preferred') -or
                    $failure.phase -isnot [string] -or
                    [string]$failure.phase -cnotin $failurePhases -or
                    [string]$failure.status -cnotin @(
                        'LAB_BLOCKED', 'PRODUCT_INVARIANT'
                    ) -or -not (& $bool $failure.fixture_certified) -or
                    -not (& $bool $failure.cleanup_complete) -or
                    $failure.cleanup_incident_codes -isnot [System.Array]) {
                    return $false
                }
                $failureMap = if ([string]$failure.status -ceq
                    'PRODUCT_INVARIANT') { $productCodes } else { $labCodes }
                if ($failure.code -isnot [string] -or
                    -not $failureMap.Contains([string]$failure.code) -or
                    $failure.category -isnot [string] -or
                    [string]$failure.category -cne
                        [string]$failureMap[[string]$failure.code] -or
                    @($failure.cleanup_incident_codes | Where-Object {
                        $_ -isnot [string] -or
                        [string]$_ -cnotin @($labCodes.Keys)
                    }).Count -ne 0) {
                    return $false
                }
            }
            if (-not (& $exact $Value.cleanup @(
                'complete', 'candidate_package_unchanged',
                'package_manifest_unchanged',
                'package_zip_binding_unchanged',
                'process_cleanup_complete', 'peer_cleanup_complete',
                'registry_and_system_state_exact'
            )) -or @($Value.cleanup.PSObject.Properties.Value |
                    Where-Object { -not (& $bool $_) }).Count -ne 0 -or
                -not (& $exact $Value.retention @(
                'private_artifacts_retained', 'private_file_count',
                'private_total_bytes',
                'private_artifact_manifest_sha256', 'public_allowlist'
            )) -or -not (& $bool `
                    $Value.retention.private_artifacts_retained) -or
                -not [bool]$Value.retention.private_artifacts_retained -or
                -not (& $positive $Value.retention.private_file_count) -or
                -not (& $positive $Value.retention.private_total_bytes) -or
                -not (& $hash `
                    $Value.retention.private_artifact_manifest_sha256) -or
                $Value.retention.public_allowlist -isnot [System.Array] -or
                @($Value.retention.public_allowlist | Where-Object {
                    $_ -isnot [string]
                }).Count -ne 0 -or
                (@($Value.retention.public_allowlist) -join '|') -cne
                    'summary.json|evidence-manifest.json') {
                return $false
            }
            $topologyCoherent =
                ([bool]$Value.topology.proved -and
                    [string]$Value.topology.class -ceq 'T1' -and
                    [bool]$Value.topology.t1_proved -and
                    -not [bool]$Value.topology.t2_proved) -or
                ([bool]$Value.topology.proved -and
                    [string]$Value.topology.class -ceq 'T2' -and
                    -not [bool]$Value.topology.t1_proved -and
                    [bool]$Value.topology.t2_proved) -or
                (-not [bool]$Value.topology.proved -and
                    [string]$Value.topology.class -ceq '' -and
                    -not [bool]$Value.topology.t1_proved -and
                    -not [bool]$Value.topology.t2_proved)
            if (-not $topologyCoherent) { return $false }
            $productFailureCount = @($Value.failures | Where-Object {
                [string]$_.status -ceq 'PRODUCT_INVARIANT'
            }).Count
            $labFailureCount = @($Value.failures | Where-Object {
                [string]$_.status -ceq 'LAB_BLOCKED'
            }).Count
            if ([Int64]$Value.adjudication.proven_product_failure_count +
                    [Int64]$Value.adjudication.
                        untrusted_product_failure_count -ne
                    $productFailureCount -or
                [Int64]$Value.adjudication.lab_incident_count -ne
                    $labFailureCount -or
                @($Value.failures | Where-Object {
                    [string]$_.status -ceq 'PRODUCT_INVARIANT' -and
                    -not [bool]$_.fixture_certified
                }).Count -gt 0) {
                return $false
            }
            $allPoliciesPass = @($Value.policies).Count -eq 2 -and
                ($policyNames -join '|') -ceq 'auto|preferred' -and
                @($Value.policies | Where-Object {
                    -not [bool]$_.fixture_valid -or
                    -not [bool]$_.product_match
                }).Count -eq 0
            $allCleanupPass = @(
                $Value.cleanup.PSObject.Properties.Value |
                    Where-Object { -not [bool]$_ }
            ).Count -eq 0
            $passEvidence = [bool]$Value.candidate.package_unchanged -and
                [bool]$Value.topology.proved -and $allPoliciesPass -and
                $allCleanupPass -and @($Value.failures).Count -eq 0 -and
                [Int64]$Value.adjudication.proven_product_failure_count -eq 0 -and
                [Int64]$Value.adjudication.untrusted_product_failure_count -eq 0 -and
                [Int64]$Value.adjudication.lab_incident_count -eq 0 -and
                [Int64]$Value.adjudication.malformed_or_stale_failure_count -eq 0
            if (([string]$Value.formal_status -ceq 'PASS' -and
                    -not $passEvidence) -or
                ([string]$Value.formal_status -ceq 'FAIL' -and
                    ([Int64]$Value.adjudication.
                        proven_product_failure_count -le 0 -or
                    $productFailureCount -le 0)) -or
                ([string]$Value.formal_status -ceq 'BLOCKED' -and
                    ([Int64]$Value.adjudication.
                        proven_product_failure_count -ne 0 -or
                    $passEvidence))) {
                return $false
            }
            return $true
        }
        if ([string]$Value.schema -ceq
            'ese.v91.i03-peer-public-summary/v1') {
            if (-not (& $exact $Value @(
                'schema', 'case_id', 'role', 'status', 'candidate',
                'barriers_completed', 'expected_barriers', 'failures',
                'cleanup', 'retention'
            )) -or [string]$Value.case_id -cne 'V91-I03' -or
                [string]$Value.role -cne 'Peer' -or
                [string]$Value.status -cnotin @(
                    'COMPLETE', 'PRODUCT_INVARIANT', 'LAB_BLOCKED'
                ) -or
                -not (& $exact $Value.candidate @(
                    'commit', 'emule_sha256', 'zip_sha256',
                    'package_unchanged'
                )) -or
                [string]$Value.candidate.commit -notmatch '^[0-9a-f]{40}$' -or
                -not (& $hash $Value.candidate.emule_sha256) -or
                -not (& $hash $Value.candidate.zip_sha256) -or
                -not (& $bool $Value.candidate.package_unchanged) -or
                -not (& $nonnegative $Value.barriers_completed) -or
                [Int64]$Value.barriers_completed -gt 2 -or
                -not (& $integer $Value.expected_barriers) -or
                [Int64]$Value.expected_barriers -ne 2 -or
                $Value.failures -isnot [System.Array]) { return $false }
            if (([string]$Value.status -ceq 'COMPLETE' -and
                    [Int64]$Value.barriers_completed -ne 2) -or
                ([string]$Value.status -cne 'COMPLETE' -and
                    @($Value.failures).Count -eq 0)) {
                return $false
            }
            foreach ($failure in @($Value.failures)) {
                if (-not (& $exact $failure @(
                    'policy', 'phase', 'status', 'category', 'code',
                    'fixture_certified', 'cleanup_complete'
                )) -or [string]$failure.policy -cnotin @(
                        'none', 'auto', 'preferred'
                    ) -or $failure.phase -isnot [string] -or
                    [string]$failure.phase -cnotin $failurePhases -or
                    [string]$failure.status -cnotin @(
                        'LAB_BLOCKED', 'PRODUCT_INVARIANT'
                    ) -or -not (& $bool $failure.fixture_certified) -or
                    -not (& $bool $failure.cleanup_complete)) {
                    return $false
                }
                $failureMap = if ([string]$failure.status -ceq
                    'PRODUCT_INVARIANT') { $productCodes } else { $labCodes }
                if ($failure.code -isnot [string] -or
                    -not $failureMap.Contains([string]$failure.code) -or
                    $failure.category -isnot [string] -or
                    [string]$failure.category -cne
                        [string]$failureMap[[string]$failure.code]) {
                    return $false
                }
            }
            if (-not (& $exact $Value.cleanup @(
                'complete', 'source_process_stopped',
                'candidate_package_unchanged',
                'registry_and_system_state_exact'
            )) -or @($Value.cleanup.PSObject.Properties.Value |
                    Where-Object { -not (& $bool $_) }).Count -ne 0 -or
                -not (& $exact $Value.retention @(
                'private_artifacts_retained',
                'coordination_private_artifacts_retained',
                'private_file_count',
                'private_artifact_manifest_sha256'
            )) -or -not (& $bool `
                    $Value.retention.private_artifacts_retained) -or
                -not [bool]$Value.retention.private_artifacts_retained -or
                -not (& $bool `
                    $Value.retention.coordination_private_artifacts_retained) -or
                -not [bool]$Value.retention.coordination_private_artifacts_retained -or
                -not (& $positive $Value.retention.private_file_count) -or
                -not (& $hash `
                    $Value.retention.private_artifact_manifest_sha256)) {
                return $false
            }
            $peerProductFailureCount = @($Value.failures |
                Where-Object {
                    [string]$_.status -ceq 'PRODUCT_INVARIANT'
                }).Count
            $peerLabFailureCount = @($Value.failures | Where-Object {
                [string]$_.status -ceq 'LAB_BLOCKED'
            }).Count
            $peerCleanupPass = @(
                $Value.cleanup.PSObject.Properties.Value |
                    Where-Object { -not [bool]$_ }
            ).Count -eq 0
            if (([string]$Value.status -ceq 'COMPLETE' -and
                    (@($Value.failures).Count -ne 0 -or
                    [Int64]$Value.barriers_completed -ne 2 -or
                    -not [bool]$Value.candidate.package_unchanged -or
                    -not $peerCleanupPass)) -or
                ([string]$Value.status -ceq 'PRODUCT_INVARIANT' -and
                    $peerProductFailureCount -le 0) -or
                ([string]$Value.status -ceq 'LAB_BLOCKED' -and
                    ($peerLabFailureCount -le 0 -or
                    $peerProductFailureCount -ne 0))) {
                return $false
            }
            return $true
        }
        return $false
    } catch { return $false }
}

function Test-I03PublicEvidenceDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$ExpectedFiles,
        [Parameter(Mandatory = $true)][string]$PrivateManifestPath
    )

    try {
        $rootPath = [IO.Path]::GetFullPath($Root)
        $rootItem = Get-Item -LiteralPath $rootPath -Force `
            -ErrorAction Stop
        if (-not $rootItem.PSIsContainer -or
            ($rootItem.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            return $false
        }
        $items = @(Get-ChildItem -LiteralPath $rootPath -Force `
            -Recurse -ErrorAction Stop)
        if (@($items | Where-Object {
                $_.PSIsContainer -or
                ($_.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0
            }).Count -ne 0) {
            return $false
        }
        $actualNames = @($items | ForEach-Object {
            $_.FullName.Substring($rootPath.TrimEnd('\').Length + 1).
                Replace('\', '/')
        } | Sort-Object)
        $expectedNames = @($ExpectedFiles | Sort-Object)
        if ($actualNames.Count -ne $expectedNames.Count -or
            ($actualNames -join '|') -cne ($expectedNames -join '|')) {
            return $false
        }
        $objectsByName = @{}
        foreach ($item in $items) {
            $text = Get-Content -LiteralPath $item.FullName -Raw `
                -ErrorAction Stop
            if (-not (Test-I03PublicEvidenceText -Text $text)) {
                return $false
            }
            $object = $text | ConvertFrom-Json -ErrorAction Stop
            if (-not (Test-I03PublicEvidenceObject -Value $object)) {
                return $false
            }
            $objectsByName[$item.Name] = $object
        }
        $summaryItem = Get-Item -LiteralPath (
            Join-Path $rootPath 'summary.json'
        ) -Force -ErrorAction Stop
        $manifest = $objectsByName['evidence-manifest.json']
        $summary = $objectsByName['summary.json']
        $manifestSummary = @($manifest.files)[0]
        if ([string]$manifestSummary.name -cne 'summary.json' -or
            [Int64]$manifestSummary.bytes -ne [Int64]$summaryItem.Length -or
            [string]$manifestSummary.sha256 -cne
                (Get-LabSha256 -Path $summaryItem.FullName)) {
            return $false
        }
        $privateManifestItem = Get-Item -LiteralPath $PrivateManifestPath `
            -Force -ErrorAction Stop
        if (($privateManifestItem.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            return $false
        }
        $privateManifestSha = Get-LabSha256 `
            -Path $privateManifestItem.FullName
        if ([string]$manifest.private_artifact_manifest_sha256 -cne
                $privateManifestSha -or
            [string]$summary.retention.
                private_artifact_manifest_sha256 -cne $privateManifestSha) {
            return $false
        }
        return $true
    } catch {
        return $false
    }
}

function Test-I03IpPrefix {
    param(
        [Parameter(Mandatory = $true)][Net.IPAddress]$Address,
        [Parameter(Mandatory = $true)][string]$Network,
        [ValidateRange(0, 128)][int]$PrefixLength
    )

    $networkAddress = [Net.IPAddress]::Parse($Network)
    if ($Address.AddressFamily -ne $networkAddress.AddressFamily) {
        return $false
    }
    $addressBytes = $Address.GetAddressBytes()
    $networkBytes = $networkAddress.GetAddressBytes()
    if ($PrefixLength -gt ($addressBytes.Length * 8)) {
        return $false
    }
    $wholeBytes = [Math]::Floor($PrefixLength / 8)
    for ($index = 0; $index -lt $wholeBytes; $index++) {
        if ($addressBytes[$index] -ne $networkBytes[$index]) {
            return $false
        }
    }
    $remainingBits = $PrefixLength % 8
    if ($remainingBits -eq 0) { return $true }
    $mask = [byte](0xff -band (0xff -shl (8 - $remainingBits)))
    return (($addressBytes[$wholeBytes] -band $mask) -eq
        ($networkBytes[$wholeBytes] -band $mask))
}

function Get-I03NativeAddressClass {
    param([Parameter(Mandatory = $true)][string]$Address)

    $parsed = $null
    if (-not [Net.IPAddress]::TryParse(
            $Address.Split('%')[0], [ref]$parsed)) {
        return 'invalid'
    }
    if ($parsed.AddressFamily -eq
        [Net.Sockets.AddressFamily]::InterNetwork) {
        $bytes = $parsed.GetAddressBytes()
        if ($bytes[0] -eq 0) { return 'special-v4' }
        if ($bytes[0] -eq 10 -or
            ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and
                $bytes[1] -le 31) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 168)) {
            return 'private-v4'
        }
        if ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and
            $bytes[1] -le 127) { return 'cgnat-v4' }
        if ($bytes[0] -eq 127) { return 'loopback-v4' }
        if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) {
            return 'linklocal-v4'
        }
        if (($bytes[0] -eq 192 -and $bytes[1] -eq 0 -and
                $bytes[2] -eq 0) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 0 -and
                $bytes[2] -eq 2) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 31 -and
                $bytes[2] -eq 196) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 52 -and
                $bytes[2] -eq 193) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 88 -and
                $bytes[2] -eq 99) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 175 -and
                $bytes[2] -eq 48) -or
            ($bytes[0] -eq 198 -and $bytes[1] -in @(18, 19)) -or
            ($bytes[0] -eq 198 -and $bytes[1] -eq 51 -and
                $bytes[2] -eq 100) -or
            ($bytes[0] -eq 203 -and $bytes[1] -eq 0 -and
                $bytes[2] -eq 113) -or $bytes[0] -ge 224) {
            return 'special-v4'
        }
        return 'global-public-v4'
    }

    if ($parsed.IsIPv4MappedToIPv6) { return 'ipv4-mapped' }
    if ($parsed.Equals([Net.IPAddress]::IPv6Any)) {
        return 'unspecified-v6'
    }
    if ($parsed.Equals([Net.IPAddress]::IPv6Loopback)) {
        return 'loopback-v6'
    }
    if ($parsed.IsIPv6Multicast) { return 'multicast-v6' }
    if ($parsed.IsIPv6LinkLocal) { return 'linklocal-v6' }
    if (Test-I03IpPrefix -Address $parsed -Network 'fc00::' `
            -PrefixLength 7) { return 'ula-v6' }
    if (Test-I03IpPrefix -Address $parsed -Network '64:ff9b::' `
            -PrefixLength 96) { return 'translation-v6' }
    if (Test-I03IpPrefix -Address $parsed -Network '64:ff9b:1::' `
            -PrefixLength 48) { return 'translation-v6' }
    if (Test-I03IpPrefix -Address $parsed -Network '2001::' `
            -PrefixLength 23) { return 'special-v6' }
    if (Test-I03IpPrefix -Address $parsed -Network '2001:db8::' `
            -PrefixLength 32) { return 'documentation-v6' }
    if (Test-I03IpPrefix -Address $parsed -Network '2002::' `
            -PrefixLength 16) { return 'transition-v6' }
    if (Test-I03IpPrefix -Address $parsed -Network '3ffe::' `
            -PrefixLength 16) { return 'former-6bone-v6' }
    if (Test-I03IpPrefix -Address $parsed -Network '3fff::' `
            -PrefixLength 20) { return 'documentation-v6' }
    if (Test-I03IpPrefix -Address $parsed -Network '2620:4f:8000::' `
            -PrefixLength 48) { return 'special-v6' }
    if (-not (Test-I03IpPrefix -Address $parsed -Network '2000::' `
                -PrefixLength 3)) { return 'non-global-v6' }
    return 'global-native-v6'
}

$peerV4Address = Convert-I03Address -Value $PeerIPv4 `
    -Family ([Net.Sockets.AddressFamily]::InterNetwork) -Name 'PeerIPv4'
$peerLocalV4Address = Convert-I03Address -Value $PeerLocalIPv4 `
    -Family ([Net.Sockets.AddressFamily]::InterNetwork) -Name 'PeerLocalIPv4'
$peerV6Address = Convert-I03Address -Value $PeerIPv6 `
    -Family ([Net.Sockets.AddressFamily]::InterNetworkV6) -Name 'PeerIPv6'
$peerV4Text = $peerV4Address.ToString()
$peerLocalV4Text = $peerLocalV4Address.ToString()
$peerV6Text = $peerV6Address.ToString()
if ((Get-I03NativeAddressClass -Address $peerV4Text) -ne
        'global-public-v4') {
    throw 'PeerIPv4 must be the real globally routable HighID endpoint'
}
if ((Get-I03NativeAddressClass -Address $peerV6Text) -ne
        'global-native-v6') {
    throw 'PeerIPv6 must be a native public global IPv6 address'
}
if ((Get-I03NativeAddressClass -Address $peerLocalV4Text) -in @(
    'invalid', 'loopback-v4', 'linklocal-v4', 'special-v4'
)) {
    throw 'PeerLocalIPv4 must be an assigned unicast address on the peer adapter'
}

$allPorts = @(
    $PeerTcpPort, $PeerUdpPort, $PeerWebPort,
    $AutoTcpPort, $AutoUdpPort, $AutoWebPort,
    $PreferredTcpPort, $PreferredUdpPort, $PreferredWebPort
)
if (@($allPorts | Sort-Object -Unique).Count -ne $allPorts.Count) {
    throw 'All peer, Auto and Preferred TCP/UDP/Web ports must be unique'
}

function Test-I03Administrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )
    } catch {
        return $false
    }
}

function Get-I03MachineIdentityEvidence {
    try {
        $machineGuid = [string](Get-ItemProperty `
            -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' `
            -Name MachineGuid -ErrorAction Stop).MachineGuid
        if ([string]::IsNullOrWhiteSpace($machineGuid)) {
            throw 'MachineGuid is empty'
        }
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem `
            -ErrorAction Stop
        if ($null -eq $computerSystem -or
            [string]::IsNullOrWhiteSpace(
                [string]$computerSystem.Manufacturer
            ) -or
            [string]::IsNullOrWhiteSpace([string]$computerSystem.Model)) {
            throw 'Win32_ComputerSystem identity is incomplete'
        }
        $manufacturer = ([string]$computerSystem.Manufacturer).Trim()
        $model = ([string]$computerSystem.Model).Trim()
        $virtualSignaturePattern =
            '(?i)vmware|virtualbox|vbox|innotek|parallels|qemu|kvm|' +
            'virtio|xen|bochs|bhyve|hyper-v|virtual machine|' +
            'hvm domu|amazon ec2|google compute engine|openstack'
        $virtualSignature = ($manufacturer + '|' + $model) -match
            $virtualSignaturePattern
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-machine-identity/v1'
            collector_ok = $true
            collector_error_code = 'NONE'
            source = 'HKLM_MACHINEGUID_AND_WIN32_COMPUTERSYSTEM'
            machine_id_sha256 = Get-LabStringSha256 -Value $machineGuid
            manufacturer = $manufacturer
            model = $model
            virtual_signature_detected = $virtualSignature
            physical_host_claim = -not $virtualSignature
        }
    } catch {
        throw 'I03_COLLECTOR::MACHINE_ID_QUERY_FAILED'
    }
}

function Get-I03MachineId {
    $identity = Get-I03MachineIdentityEvidence
    if (-not [bool]$identity.collector_ok -or
        [string]$identity.machine_id_sha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'I03_COLLECTOR::MACHINE_ID_QUERY_FAILED'
    }
    return [string]$identity.machine_id_sha256
}

function Get-I03PackageIdentity {
    param([Parameter(Mandatory = $true)][string]$PackagePath)

    $root = Get-LabFullPath -Path $PackagePath
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'I03_ZIP_BINDING::PACKAGE_ROOT_REPARSE_OR_INVALID'
    }
    $rootPrefix = $root.TrimEnd('\') + '\'
    $allItems = [System.Collections.Generic.List[object]]::new()
    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($root)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force `
                -ErrorAction Stop)) {
            $fullName = [IO.Path]::GetFullPath([string]$item.FullName)
            if (-not $fullName.StartsWith(
                    $rootPrefix, [StringComparison]::OrdinalIgnoreCase) -or
                ($item.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'I03_ZIP_BINDING::PACKAGE_REPARSE_OR_ESCAPE'
            }
            $allItems.Add($item)
            if ($item.PSIsContainer) { $pending.Push($fullName) }
        }
    }
    $entries = [System.Collections.Generic.List[object]]::new()
    $totalBytes = 0L
    foreach ($file in @(
        $allItems | Where-Object { -not $_.PSIsContainer } |
            Sort-Object FullName
    )) {
        $relative = $file.FullName.Substring($root.Length).
            TrimStart('\').Replace('\', '/')
        $sha256 = Get-LabSha256 -Path $file.FullName
        $totalBytes += [Int64]$file.Length
        $entries.Add([pscustomobject][ordered]@{
            relative_path = $relative
            bytes = [Int64]$file.Length
            sha256 = $sha256
        })
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-extracted-package-manifest/v1'
        package_directory_name = Split-Path -Leaf $root
        file_count = $entries.Count
        total_bytes = $totalBytes
        manifest_sha256 = Get-I03PackageManifestSha256 -Entries $entries
        files = @($entries)
    }
}

function Get-I03PackageManifestSha256 {
    param([Parameter(Mandatory = $true)][object[]]$Entries)

    $canonical = New-Object Text.StringBuilder
    foreach ($entry in @($Entries | Sort-Object {
                [string]$_.relative_path
            })) {
        $null = $canonical.Append([string]$entry.relative_path)
        $null = $canonical.Append([char]0)
        $null = $canonical.Append([string][Int64]$entry.bytes)
        $null = $canonical.Append([char]0)
        $null = $canonical.Append(
            ([string]$entry.sha256).ToLowerInvariant())
        $null = $canonical.Append("`n")
    }
    return Get-LabStringSha256 -Value $canonical.ToString()
}

function New-I03PreparedPreferencesOracle {
    param(
        [Parameter(Mandatory = $true)][string]$PackagePath,
        [Parameter(Mandatory = $true)][object]$PackageIdentity,
        [Parameter(Mandatory = $true)][string]$OracleRoot,
        [Parameter(Mandatory = $true)]
        [ValidateSet('A', 'B')][string]$NodeRole,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9._-]{1,64}$')][string]$RunId,
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 60000)][int]$PortOffset
    )

    $result = [ordered]@{
        schema = 'ese.v91.i03-prepared-preferences-oracle/v1'
        collector_ok = $false
        collector_error_code = 'ORACLE_NOT_EVALUATED'
        source_bound = $false
        source_preferences_sha256 = ''
        source_preferences_bytes = 0
        expected_prepared_preferences_sha256 = ''
        expected_prepared_preferences_bytes = 0
    }
    try {
        $rows = @($PackageIdentity.files | Where-Object {
            [string]$_.relative_path -ceq 'config/preferences.ini'
        })
        if ($rows.Count -ne 1 -or
            [string]$rows[0].sha256 -notmatch '^[0-9a-f]{64}$' -or
            [Int64]$rows[0].bytes -lt 0) {
            $result.collector_ok = $true
            $result.collector_error_code = 'NONE'
            return [pscustomobject]$result
        }
        $packageRoot = Get-LabFullPath -Path $PackagePath
        $sourcePath = Get-LabFullPath -Path (
            Join-Path $packageRoot 'config\preferences.ini'
        )
        $packagePrefix = $packageRoot.TrimEnd('\') + '\'
        $sourceItem = Get-Item -LiteralPath $sourcePath -Force `
            -ErrorAction Stop
        if (-not $sourcePath.StartsWith(
                $packagePrefix,
                [StringComparison]::OrdinalIgnoreCase) -or
            $sourceItem.PSIsContainer -or
            ($sourceItem.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            $result.collector_ok = $true
            $result.collector_error_code = 'NONE'
            return [pscustomobject]$result
        }
        $stream = [IO.FileStream]::new(
            $sourcePath, [IO.FileMode]::Open, [IO.FileAccess]::Read,
            [IO.FileShare]::None
        )
        try {
            $memory = [IO.MemoryStream]::new()
            try {
                $stream.CopyTo($memory)
                $sourceBytes = $memory.ToArray()
            } finally { $memory.Dispose() }
        } finally { $stream.Dispose() }
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $sourceSha = ([BitConverter]::ToString(
                $sha.ComputeHash($sourceBytes)
            )).Replace('-', '').ToLowerInvariant()
        } finally { $sha.Dispose() }
        $result.source_preferences_sha256 = $sourceSha
        $result.source_preferences_bytes = [Int64]$sourceBytes.Length
        $result.source_bound = $sourceSha -ceq
                [string]$rows[0].sha256 -and
            [Int64]$sourceBytes.Length -eq [Int64]$rows[0].bytes
        if (-not [bool]$result.source_bound) {
            $result.collector_ok = $true
            $result.collector_error_code = 'NONE'
            return [pscustomobject]$result
        }

        $root = New-LabDirectory -Path $OracleRoot
        $shadowPackage = Join-Path $root 'frozen-source'
        $oracleNodes = Join-Path $root 'prepared'
        if ((Test-Path -LiteralPath $shadowPackage) -or
            (Test-Path -LiteralPath $oracleNodes)) {
            throw 'Oracle directory is not empty'
        }
        $null = New-Item -ItemType Directory -Path $shadowPackage
        $null = New-Item -ItemType Directory `
            -Path (Join-Path $shadowPackage 'config')
        $null = New-Item -ItemType Directory -Path $oracleNodes
        [IO.File]::WriteAllBytes(
            (Join-Path $shadowPackage 'emule.exe'), [byte[]]@()
        )
        [IO.File]::WriteAllBytes(
            (Join-Path $shadowPackage 'config\preferences.ini'),
            $sourceBytes
        )
        & (Join-Path $PSScriptRoot 'prepare_node.ps1') `
            -NodeRole $NodeRole -SourcePackage $shadowPackage `
            -OutputRoot $oracleNodes -RunId $RunId `
            -PortOffset $PortOffset
        $preparedPreferences = Join-Path $oracleNodes (
            '{0}-{1}\config\preferences.ini' -f
                $RunId, $NodeRole.ToLowerInvariant()
        )
        $preparedItem = Get-Item -LiteralPath $preparedPreferences `
            -Force -ErrorAction Stop
        if (($preparedItem.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Prepared oracle preferences is a reparse point'
        }
        $result.expected_prepared_preferences_sha256 =
            Get-LabSha256 -Path $preparedPreferences
        $result.expected_prepared_preferences_bytes =
            [Int64]$preparedItem.Length
        $result.collector_ok = $true
        $result.collector_error_code = 'NONE'
        return [pscustomobject]$result
    } catch {
        $result.collector_error_code = 'PREFERENCES_ORACLE_FAILED'
        return [pscustomobject]$result
    }
}

function Test-I03PreparedNodeBinding {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][object]$PackageIdentity,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Initial', 'Terminal')][string]$Phase,
        [string]$ExpectedPreparedPreferencesSha256 = '',
        [Int64]$ExpectedPreparedPreferencesBytes = -1
    )

    $result = [ordered]@{
        schema = 'ese.v91.i03-prepared-node-binding/v1'
        phase = $Phase.ToLowerInvariant()
        collector_ok = $false
        collector_error_code = 'NODE_BINDING_NOT_EVALUATED'
        bound = $false
        binding_error_code = 'NONE'
        package_manifest_sha256 = ''
        expected_package_file_count = 0
        observed_node_file_count = 0
        verified_immutable_file_count = 0
        verified_immutable_manifest_sha256 = ''
        mutable_package_exclusions = @('config/preferences.ini')
        prepared_preferences_sha256 = ''
        prepared_preferences_bytes = 0
        deterministic_preferences_match = $false
        allowed_initial_extra_files = @('LAB_NODE.json')
    }
    try {
        if ([string]$PackageIdentity.schema -cne
                'ese.v91.i03-extracted-package-manifest/v1' -or
            [string]$PackageIdentity.manifest_sha256 -notmatch
                '^[0-9a-f]{64}$' -or
            $PackageIdentity.files -isnot [System.Array]) {
            $result.collector_ok = $true
            $result.collector_error_code = 'NONE'
            $result.binding_error_code = 'PACKAGE_IDENTITY_INVALID'
            return [pscustomobject]$result
        }
        $result.package_manifest_sha256 =
            [string]$PackageIdentity.manifest_sha256
        $result.expected_package_file_count =
            [int]@($PackageIdentity.files).Count
        $expected = [System.Collections.Generic.Dictionary[
            string,object]]::new([StringComparer]::Ordinal)
        foreach ($row in @($PackageIdentity.files)) {
            $relative = [string]$row.relative_path
            if ([string]::IsNullOrWhiteSpace($relative) -or
                $relative.StartsWith('/') -or $relative.Contains('\') -or
                @($relative.Split('/') | Where-Object {
                    [string]$_ -cin @('', '.', '..')
                }).Count -gt 0 -or
                $row.bytes -is [bool] -or
                $row.bytes -isnot [ValueType] -or
                [Int64]$row.bytes -lt 0 -or
                [string]$row.sha256 -notmatch '^[0-9a-f]{64}$' -or
                $expected.ContainsKey($relative)) {
                $result.collector_ok = $true
                $result.collector_error_code = 'NONE'
                $result.binding_error_code = 'PACKAGE_FILE_ROW_INVALID'
                return [pscustomobject]$result
            }
            $expected.Add($relative, $row)
        }
        if ($expected.Count -ne [int]$PackageIdentity.file_count -or
            -not $expected.ContainsKey('config/preferences.ini') -or
            -not $expected.ContainsKey('emule.exe') -or
            -not $expected.ContainsKey('ese-server.exe') -or
            -not $expected.ContainsKey('BUILD_INFO.txt')) {
            $result.collector_ok = $true
            $result.collector_error_code = 'NONE'
            $result.binding_error_code = 'PACKAGE_FILE_SET_INVALID'
            return [pscustomobject]$result
        }

        $root = Get-LabFullPath -Path $NodePath
        $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
        if (-not $rootItem.PSIsContainer -or
            ($rootItem.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            $result.collector_ok = $true
            $result.collector_error_code = 'NONE'
            $result.binding_error_code = 'NODE_ROOT_INVALID'
            return [pscustomobject]$result
        }
        $rootPrefix = $root.TrimEnd('\') + '\'
        $items = @(Get-ChildItem -LiteralPath $root -Force -Recurse `
            -ErrorAction Stop)
        if (@($items | Where-Object {
                ($_.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0
            }).Count -gt 0) {
            $result.collector_ok = $true
            $result.collector_error_code = 'NONE'
            $result.binding_error_code = 'NODE_REPARSE_POINT'
            return [pscustomobject]$result
        }
        $files = @($items | Where-Object { -not $_.PSIsContainer })
        $result.observed_node_file_count = $files.Count
        $actual = [System.Collections.Generic.Dictionary[
            string,object]]::new([StringComparer]::Ordinal)
        foreach ($file in $files) {
            $full = [IO.Path]::GetFullPath([string]$file.FullName)
            if (-not $full.StartsWith(
                    $rootPrefix,
                    [StringComparison]::OrdinalIgnoreCase)) {
                $result.collector_ok = $true
                $result.collector_error_code = 'NONE'
                $result.binding_error_code = 'NODE_PATH_ESCAPE'
                return [pscustomobject]$result
            }
            $relative = $full.Substring($rootPrefix.Length).
                Replace('\', '/')
            if ($actual.ContainsKey($relative)) {
                $result.collector_ok = $true
                $result.collector_error_code = 'NONE'
                $result.binding_error_code = 'NODE_PATH_DUPLICATE'
                return [pscustomobject]$result
            }
            $actual.Add($relative, $file)
        }

        if ($Phase -ceq 'Initial') {
            if ($ExpectedPreparedPreferencesSha256 -notmatch
                    '^[0-9a-f]{64}$' -or
                $ExpectedPreparedPreferencesBytes -lt 0) {
                $result.collector_ok = $true
                $result.collector_error_code = 'NONE'
                $result.binding_error_code =
                    'EXPECTED_PREPARED_PREFERENCES_MISSING'
                return [pscustomobject]$result
            }
            if ($actual.Count -ne ($expected.Count + 1) -or
                -not $actual.ContainsKey('LAB_NODE.json') -or
                @($actual.Keys | Where-Object {
                    [string]$_ -cne 'LAB_NODE.json' -and
                    -not $expected.ContainsKey([string]$_)
                }).Count -gt 0 -or
                @($expected.Keys | Where-Object {
                    -not $actual.ContainsKey([string]$_)
                }).Count -gt 0) {
                $result.collector_ok = $true
                $result.collector_error_code = 'NONE'
                $result.binding_error_code = 'INITIAL_FILE_SET_MISMATCH'
                return [pscustomobject]$result
            }
            $preparedPreferences =
                $actual['config/preferences.ini']
            $result.prepared_preferences_bytes =
                [Int64]$preparedPreferences.Length
            $result.prepared_preferences_sha256 =
                Get-LabSha256 -Path ([string]$preparedPreferences.FullName)
            $result.deterministic_preferences_match =
                [Int64]$preparedPreferences.Length -eq
                    $ExpectedPreparedPreferencesBytes -and
                [string]$result.prepared_preferences_sha256 -ceq
                    $ExpectedPreparedPreferencesSha256
            if (-not [bool]$result.deterministic_preferences_match) {
                $result.collector_ok = $true
                $result.collector_error_code = 'NONE'
                $result.binding_error_code = 'PREPARED_PREFERENCES_MISMATCH'
                return [pscustomobject]$result
            }
            $nodeManifest = Get-Content -LiteralPath (
                [string]$actual['LAB_NODE.json'].FullName
            ) -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if ([string]$nodeManifest.schema -cne 'ese.lab.node/v1' -or
                $nodeManifest.launch_performed -isnot [bool] -or
                [bool]$nodeManifest.launch_performed) {
                $result.collector_ok = $true
                $result.collector_error_code = 'NONE'
                $result.binding_error_code = 'NODE_MANIFEST_INVALID'
                return [pscustomobject]$result
            }
            $rowsToVerify = @($PackageIdentity.files | Where-Object {
                [string]$_.relative_path -cne 'config/preferences.ini'
            })
        } else {
            $unexpectedStatic = @($actual.Keys | Where-Object {
                $relative = [string]$_
                $extension = [IO.Path]::GetExtension($relative)
                ($extension -cin @('.exe', '.dll')) -and
                    -not $expected.ContainsKey($relative)
            })
            if ($unexpectedStatic.Count -gt 0) {
                $result.collector_ok = $true
                $result.collector_error_code = 'NONE'
                $result.binding_error_code = 'UNEXPECTED_STATIC_FILE'
                return [pscustomobject]$result
            }
            $rowsToVerify = @($PackageIdentity.files | Where-Object {
                $relative = [string]$_.relative_path
                $extension = [IO.Path]::GetExtension($relative)
                $extension -cin @('.exe', '.dll') -or
                    $relative -ceq 'BUILD_INFO.txt'
            })
            if (@($rowsToVerify).Count -lt 3) {
                $result.collector_ok = $true
                $result.collector_error_code = 'NONE'
                $result.binding_error_code = 'STATIC_FILE_SET_INCOMPLETE'
                return [pscustomobject]$result
            }
        }

        foreach ($row in $rowsToVerify) {
            $relative = [string]$row.relative_path
            if (-not $actual.ContainsKey($relative)) {
                $result.collector_ok = $true
                $result.collector_error_code = 'NONE'
                $result.binding_error_code = 'IMMUTABLE_FILE_MISSING'
                return [pscustomobject]$result
            }
            $file = $actual[$relative]
            if ([Int64]$file.Length -ne [Int64]$row.bytes -or
                (Get-LabSha256 -Path ([string]$file.FullName)) -cne
                    [string]$row.sha256) {
                $result.collector_ok = $true
                $result.collector_error_code = 'NONE'
                $result.binding_error_code = 'IMMUTABLE_FILE_MISMATCH'
                return [pscustomobject]$result
            }
        }
        $result.collector_ok = $true
        $result.collector_error_code = 'NONE'
        $result.bound = $true
        $result.binding_error_code = 'NONE'
        $result.verified_immutable_file_count = @($rowsToVerify).Count
        $result.verified_immutable_manifest_sha256 =
            Get-I03PackageManifestSha256 -Entries @($rowsToVerify)
        return [pscustomobject]$result
    } catch {
        $result.collector_error_code = 'NODE_BINDING_COLLECTOR_FAILED'
        return [pscustomobject]$result
    }
}

function Get-I03ZipPackageBinding {
    param(
        [Parameter(Mandatory = $true)][string]$ZipPath,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-fA-F]{64}$')]
        [string]$ExpectedZipSha256,
        [Parameter(Mandatory = $true)][object]$PackageIdentity
    )

    $zip = Get-LabFullPath -Path $ZipPath
    if (-not (Test-Path -LiteralPath $zip -PathType Leaf)) {
        throw 'I03_ZIP_BINDING::MISSING_ZIP'
    }
    $zipItem = Get-Item -LiteralPath $zip -Force
    if (($zipItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'I03_ZIP_BINDING::ZIP_REPARSE_POINT'
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zipStream = [IO.File]::Open(
        $zip, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::None)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $zipSha = ([BitConverter]::ToString(
            $sha256.ComputeHash($zipStream))).Replace('-', '').
            ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
    if ($zipSha -cne $ExpectedZipSha256.ToLowerInvariant()) {
        $zipStream.Dispose()
        throw 'I03_ZIP_BINDING::ZIP_SHA256_MISMATCH'
    }
    $zipStream.Position = 0
    $archive = [IO.Compression.ZipArchive]::new(
        $zipStream, [IO.Compression.ZipArchiveMode]::Read, $false
    )
    try {
        $packageByPath =
            [System.Collections.Generic.Dictionary[string,object]]::new(
                [StringComparer]::OrdinalIgnoreCase
            )
        foreach ($file in @($PackageIdentity.files)) {
            $relative = [string]$file.relative_path
            if ($packageByPath.ContainsKey($relative)) {
                throw 'I03_ZIP_BINDING::PACKAGE_CASE_COLLISION'
            }
            $packageByPath.Add($relative, $file)
        }

        $zipByPath =
            [System.Collections.Generic.Dictionary[string,object]]::new(
                [StringComparer]::OrdinalIgnoreCase
            )
        $rootName = $null
        foreach ($entry in @($archive.Entries)) {
            $entryName = [string]$entry.FullName
            if ([string]::IsNullOrWhiteSpace($entryName) -or
                $entryName.Contains('\') -or $entryName.StartsWith('/') -or
                $entryName -match '^[A-Za-z]:' -or
                $entryName.IndexOf([char]0) -ge 0) {
                throw 'I03_ZIP_BINDING::UNSAFE_ENTRY_PATH'
            }
            $rawSegments = @($entryName.Split('/'))
            $isDirectoryEntry =
                [string]::IsNullOrEmpty([string]$entry.Name)
            for ($segmentIndex = 0;
                $segmentIndex -lt $rawSegments.Count;
                $segmentIndex++) {
                $segment = [string]$rawSegments[$segmentIndex]
                $allowedTrailingEmpty = $isDirectoryEntry -and
                    $segmentIndex -eq ($rawSegments.Count - 1)
                if ((-not $segment -and -not $allowedTrailingEmpty) -or
                    $segment -in @('.', '..') -or
                    $segment.Contains(':') -or
                    $segment.EndsWith('.') -or $segment.EndsWith(' ') -or
                    $segment -match
                        '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)') {
                    throw 'I03_ZIP_BINDING::UNSAFE_ENTRY_PATH'
                }
            }
            $trimmed = $entryName.TrimEnd('/')
            $segments = @($trimmed.Split('/'))
            if ($segments.Count -eq 0) {
                throw 'I03_ZIP_BINDING::UNSAFE_ENTRY_PATH'
            }
            $entryRoot = [string]$segments[0]
            if ($null -eq $rootName) { $rootName = $entryRoot }
            if ($entryRoot -cne $rootName) {
                throw 'I03_ZIP_BINDING::MULTIPLE_ROOTS'
            }

            $external = [uint32]([int64]$entry.ExternalAttributes -band
                0xffffffffL)
            $unixType = ($external -shr 16) -band 0xf000
            $dosAttributes = $external -band 0xffff
            if ($unixType -eq 0xa000 -or
                ($dosAttributes -band 0x0400) -ne 0) {
                throw 'I03_ZIP_BINDING::LINK_OR_REPARSE_ENTRY'
            }
            if ([string]::IsNullOrEmpty([string]$entry.Name)) {
                continue
            }
            if ($segments.Count -lt 2) {
                throw 'I03_ZIP_BINDING::FILE_OUTSIDE_SINGLE_ROOT'
            }
            $relative = ($segments[1..($segments.Count - 1)] -join '/')
            if ($zipByPath.ContainsKey($relative)) {
                throw 'I03_ZIP_BINDING::DUPLICATE_OR_CASE_COLLISION'
            }
            $stream = $entry.Open()
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                $entrySha = ([BitConverter]::ToString(
                    $sha.ComputeHash($stream))).Replace('-', '').
                    ToLowerInvariant()
            } finally {
                $sha.Dispose()
                $stream.Dispose()
            }
            $zipByPath.Add($relative, [pscustomobject][ordered]@{
                relative_path = $relative
                bytes = [Int64]$entry.Length
                sha256 = $entrySha
            })
        }
        if ($zipByPath.Count -eq 0 -or
            $zipByPath.Count -ne $packageByPath.Count) {
            throw 'I03_ZIP_BINDING::FILE_SET_MISMATCH'
        }
        foreach ($relative in @($packageByPath.Keys)) {
            if (-not $zipByPath.ContainsKey($relative)) {
                throw 'I03_ZIP_BINDING::FILE_SET_MISMATCH'
            }
            $packageEntry = $packageByPath[$relative]
            $zipEntry = $zipByPath[$relative]
            if ([string]$zipEntry.relative_path -cne
                    [string]$packageEntry.relative_path -or
                [Int64]$zipEntry.bytes -ne [Int64]$packageEntry.bytes -or
                [string]$zipEntry.sha256 -cne
                    [string]$packageEntry.sha256) {
                throw 'I03_ZIP_BINDING::ENTRY_MISMATCH'
            }
        }
        $zipEntries = @($zipByPath.Values)
        $zipManifestSha = Get-I03PackageManifestSha256 `
            -Entries $zipEntries
        if ($zipManifestSha -cne
            [string]$PackageIdentity.manifest_sha256) {
            throw 'I03_ZIP_BINDING::MANIFEST_MISMATCH'
        }
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-package-zip-binding/v1'
            verified = $true
            zip_sha256 = $zipSha
            zip_bytes = [Int64]$zipStream.Length
            archive_root_sha256 = Get-LabStringSha256 -Value $rootName
            file_count = $zipByPath.Count
            total_bytes = [Int64]$PackageIdentity.total_bytes
            manifest_sha256 = $zipManifestSha
            exact_file_set = $true
            exact_bytes_and_sha256 = $true
            safe_single_root = $true
        }
    } finally {
        $archive.Dispose()
        $zipStream.Dispose()
    }
}

function Test-I03FailurePhase {
    param([AllowNull()][object]$Phase)

    return $Phase -is [string] -and [string]$Phase -cin @(
        'preflight', 'dualstack_rearm', 'ipv4_prewarm',
        'peer_restart', 'peer_completion', 'cleanup',
        'case_setup', 'identity_bootstrap', 'candidate_startup',
        'link_injection', 'backlog_revalidation',
        'post_restart_route', 'evidence_finalize'
    )
}

function New-I03ProofProjection {
    param(
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)][string]$CaseId,
        [Parameter(Mandatory = $true)][string]$RunNonce,
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][string]$Policy,
        [Parameter(Mandatory = $true)][string]$Phase,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-fA-F]{64}$')]
        [string]$SourceEvidenceSha256
    )

    if (-not (Test-I03FailurePhase -Phase $Phase)) {
        throw 'I03_FAILURE_PROTOCOL::UNKNOWN_PHASE'
    }
    $sourceHash = $SourceEvidenceSha256.ToLowerInvariant()
    $binding = '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f
        $CaseId, $RunNonce, $Role, $Policy, $Phase, $Kind, $sourceHash
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-proof/v1'
        case_id = $CaseId
        run_nonce = $RunNonce
        role = $Role
        policy = $Policy
        phase = $Phase
        kind = $Kind
        source_evidence_sha256 = $sourceHash
        binding_sha256 = Get-LabStringSha256 -Value $binding
    }
}

function New-I03FailureRecord {
    param(
        [Parameter(Mandatory = $true)][string]$CaseId,
        [Parameter(Mandatory = $true)][string]$RunNonce,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Coordinator', 'Peer')][string]$Role,
        [ValidateSet('none', 'auto', 'preferred')][string]$Policy = 'none',
        [Parameter(Mandatory = $true)][string]$Phase,
        [Parameter(Mandatory = $true)]
        [ValidateSet('LAB_BLOCKED', 'PRODUCT_INVARIANT')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Code,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Message,
        [Parameter(Mandatory = $true)][string]$CandidateCommit,
        [Parameter(Mandatory = $true)][string]$CandidateEmuleSha256,
        [Parameter(Mandatory = $true)][string]$CandidateZipSha256,
        [Parameter(Mandatory = $true)][string]$PackageManifestSha256,
        [Parameter(Mandatory = $true)][bool]$FixtureCertified,
        [object[]]$Proofs = @()
    )

    if (-not (Test-I03FailurePhase -Phase $Phase)) {
        throw 'I03_FAILURE_PROTOCOL::UNKNOWN_PHASE'
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-failure/v1'
        case_id = $CaseId
        run_nonce = $RunNonce
        role = $Role
        policy = $Policy
        phase = $Phase
        status = $Status
        category = $Category
        code = $Code
        message_sha256 = Get-LabStringSha256 -Value $Message
        candidate = [pscustomobject][ordered]@{
            commit = $CandidateCommit
            emule_sha256 = $CandidateEmuleSha256
            zip_sha256 = $CandidateZipSha256
            manifest_sha256 = $PackageManifestSha256
        }
        fixture_certified = $FixtureCertified
        proofs = @($Proofs)
        cleanup = [pscustomobject][ordered]@{
            complete = $false
            incident_codes = @()
        }
    }
}

function Test-I03FailureRecord {
    param(
        [AllowNull()][object]$Record,
        [Parameter(Mandatory = $true)][string]$ExpectedCaseId,
        [Parameter(Mandatory = $true)][string]$ExpectedRunNonce,
        [Parameter(Mandatory = $true)][string]$ExpectedRole,
        [Parameter(Mandatory = $true)][string]$ExpectedCommit,
        [Parameter(Mandatory = $true)][string]$ExpectedEmuleSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedZipSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedManifestSha256,
        [ValidateSet('', 'none', 'auto', 'preferred')]
        [string]$ExpectedPolicy = ''
    )

    if ($null -eq $Record) { return $false }
    $required = @(
        'schema', 'case_id', 'run_nonce', 'role', 'policy', 'phase',
        'status', 'category', 'code', 'message_sha256', 'candidate',
        'fixture_certified', 'proofs', 'cleanup'
    )
    try {
        $names = @($Record.PSObject.Properties.Name)
    } catch { return $false }
    if ($names.Count -ne $required.Count -or
        @($required | Where-Object { $names -cnotcontains $_ }).Count -gt 0 -or
        $null -eq $Record.candidate -or
        $null -eq $Record.cleanup -or
        $null -eq $Record.proofs) {
        return $false
    }
    try {
        $candidateNames = @($Record.candidate.PSObject.Properties.Name)
        $cleanupNames = @($Record.cleanup.PSObject.Properties.Name)
    } catch { return $false }
    if ($candidateNames.Count -ne 4 -or
        @('commit', 'emule_sha256', 'zip_sha256', 'manifest_sha256' |
            Where-Object { $candidateNames -cnotcontains $_ }).Count -gt 0 -or
        $cleanupNames.Count -ne 2 -or
        @('complete', 'incident_codes' | Where-Object {
                $cleanupNames -cnotcontains $_
            }).Count -gt 0) {
        return $false
    }
    if (
        $Record.schema -isnot [string] -or
        $Record.case_id -isnot [string] -or
        $Record.run_nonce -isnot [string] -or
        $Record.role -isnot [string] -or
        $Record.policy -isnot [string] -or
        $Record.phase -isnot [string] -or
        $Record.status -isnot [string] -or
        $Record.category -isnot [string] -or
        $Record.code -isnot [string] -or
        $Record.message_sha256 -isnot [string] -or
        $Record.candidate.commit -isnot [string] -or
        $Record.candidate.emule_sha256 -isnot [string] -or
        $Record.candidate.zip_sha256 -isnot [string] -or
        $Record.candidate.manifest_sha256 -isnot [string] -or
        [string]$Record.schema -cne 'ese.v91.i03-failure/v1' -or
        [string]$Record.case_id -cne $ExpectedCaseId -or
        [string]$Record.run_nonce -cne $ExpectedRunNonce -or
        [string]$Record.role -cnotin @('Coordinator', 'Peer') -or
        [string]$Record.role -cne $ExpectedRole -or
        [string]$Record.policy -cnotin @('none', 'auto', 'preferred') -or
        ($ExpectedPolicy -and
            [string]$Record.policy -cne $ExpectedPolicy) -or
        -not (Test-I03FailurePhase -Phase $Record.phase) -or
        [string]$Record.message_sha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]$Record.candidate.commit -cne $ExpectedCommit -or
        [string]$Record.candidate.emule_sha256 -cne
            $ExpectedEmuleSha256 -or
        [string]$Record.candidate.zip_sha256 -cne $ExpectedZipSha256 -or
        [string]$Record.candidate.manifest_sha256 -cne
            $ExpectedManifestSha256 -or
        $Record.fixture_certified -isnot [bool] -or
        $Record.cleanup.complete -isnot [bool] -or
        $Record.cleanup.incident_codes -isnot [System.Array] -or
        $Record.proofs -isnot [System.Array]) {
        return $false
    }

    $productCodes = [ordered]@{
        CANDIDATE_EXITED = 'PRODUCT_RUNTIME'
        UI_UNRESPONSIVE = 'PRODUCT_LIVENESS'
        API_UNAVAILABLE = 'PRODUCT_LIVENESS'
        API_CONTRACT = 'PRODUCT_CONTRACT'
        LINK_REJECTED = 'PRODUCT_INPUT'
        IPV4_PREWARM_INVARIANT = 'PRODUCT_ROUTE'
        PEER_IDENTITY_CHANGED = 'PRODUCT_IDENTITY'
        NO_ROUTE = 'PRODUCT_ROUTE'
        WRONG_FAMILY = 'PRODUCT_ROUTE'
        DUPLICATE_ROUTE = 'PRODUCT_ROUTE'
        WRONG_OR_NONPHYSICAL_SOCKET = 'PRODUCT_ATTRIBUTION'
        CANDIDATE_THIRD_PARTY_SOCKET = 'PRODUCT_ATTRIBUTION'
    }
    $labCodes = [ordered]@{
        PACKAGE_BINDING = 'LAB_PACKAGE'
        TOPOLOGY = 'LAB_TOPOLOGY'
        CLOCK = 'LAB_CLOCK'
        CONTROL_TIMEOUT = 'LAB_CONTROL'
        COORDINATION_SCHEMA = 'LAB_CONTROL'
        COLLECTOR_UNAVAILABLE = 'LAB_COLLECTOR'
        COLLECTOR_AMBIGUOUS = 'LAB_COLLECTOR'
        EXTERNAL_CONTAMINATION = 'LAB_CONTAMINATION'
        EVIDENCE_INCOMPLETE = 'LAB_EVIDENCE'
        CLEANUP_INCOMPLETE = 'LAB_CLEANUP'
        HARNESS_EXCEPTION = 'LAB_HARNESS'
    }
    $code = [string]$Record.code
    if ([string]$Record.status -ceq 'PRODUCT_INVARIANT') {
        if (-not $productCodes.Contains($code) -or
            [string]$Record.category -cne [string]$productCodes[$code] -or
            -not [bool]$Record.fixture_certified -or
            @($Record.proofs).Count -ne 1) {
            return $false
        }
        if ([string]$Record.policy -cnotin @('auto', 'preferred')) {
            return $false
        }
    } elseif ([string]$Record.status -ceq 'LAB_BLOCKED') {
        if (-not $labCodes.Contains($code) -or
            [string]$Record.category -cne [string]$labCodes[$code] -or
            @($Record.proofs).Count -ne 0) {
            return $false
        }
    } else { return $false }
    foreach ($proof in @($Record.proofs)) {
        if ($null -eq $proof) { return $false }
        $proofNames = @($proof.PSObject.Properties.Name)
        if ($proofNames.Count -ne 9 -or
            @(
                'schema', 'case_id', 'run_nonce', 'role', 'policy',
                'phase', 'kind', 'source_evidence_sha256', 'binding_sha256' |
                Where-Object {
                    $proofNames -cnotcontains $_
                }
            ).Count -gt 0 -or
            $proof.schema -isnot [string] -or
            $proof.case_id -isnot [string] -or
            $proof.run_nonce -isnot [string] -or
            $proof.role -isnot [string] -or
            $proof.policy -isnot [string] -or
            $proof.phase -isnot [string] -or
            $proof.kind -isnot [string] -or
            $proof.source_evidence_sha256 -isnot [string] -or
            $proof.binding_sha256 -isnot [string] -or
            [string]$proof.schema -cne 'ese.v91.i03-proof/v1' -or
            [string]$proof.case_id -cne [string]$Record.case_id -or
            [string]$proof.run_nonce -cne [string]$Record.run_nonce -or
            [string]$proof.role -cne [string]$Record.role -or
            [string]$proof.policy -cne [string]$Record.policy -or
            [string]$proof.phase -cne [string]$Record.phase -or
            [string]$proof.kind -cne $code.ToLowerInvariant() -or
            [string]$proof.source_evidence_sha256 -notmatch
                '^[0-9a-f]{64}$' -or
            [string]$proof.binding_sha256 -cne (
                Get-LabStringSha256 -Value (
                    '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f
                    $proof.case_id, $proof.run_nonce, $proof.role,
                    $proof.policy, $proof.phase, $proof.kind,
                    $proof.source_evidence_sha256
                )
            )) {
            return $false
        }
    }
    foreach ($incidentCode in @($Record.cleanup.incident_codes)) {
        if ($incidentCode -isnot [string] -or
            [string]$incidentCode -cnotin @($labCodes.Keys)) {
            return $false
        }
    }
    return $true
}

function Get-I03FormalAdjudication {
    param(
        [object[]]$FailureRecords = @(),
        [Parameter(Mandatory = $true)][string[]]$AllowedRolePolicyTuples,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()][string[]]$TrustedProofBindings,
        [Parameter(Mandatory = $true)][bool]$FixtureComplete,
        [Parameter(Mandatory = $true)][bool]$BothPoliciesPass,
        [Parameter(Mandatory = $true)][bool]$EvidenceComplete,
        [Parameter(Mandatory = $true)][bool]$CleanupComplete,
        [Parameter(Mandatory = $true)][string]$ExpectedCaseId,
        [Parameter(Mandatory = $true)][string]$ExpectedRunNonce,
        [Parameter(Mandatory = $true)][string]$ExpectedCommit,
        [Parameter(Mandatory = $true)][string]$ExpectedEmuleSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedZipSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedManifestSha256
    )

    $allowedContexts = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($tuple in $AllowedRolePolicyTuples) {
        if ([string]$tuple -notmatch
            '^(Coordinator|Peer)\|(none|auto|preferred)$') {
            throw 'I03_ADJUDICATION::INVALID_ALLOWED_CONTEXT'
        }
        [void]$allowedContexts.Add([string]$tuple)
    }
    $trustedBindings = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($binding in $TrustedProofBindings) {
        if ([string]$binding -notmatch '^[0-9a-f]{64}$') {
            throw 'I03_ADJUDICATION::INVALID_TRUSTED_BINDING'
        }
        [void]$trustedBindings.Add([string]$binding)
    }
    $valid = @($FailureRecords | Where-Object {
        $context = '{0}|{1}' -f ([string]$_.role),
            ([string]$_.policy)
        $allowedContexts.Contains($context) -and
        (Test-I03FailureRecord -Record $_ `
            -ExpectedCaseId $ExpectedCaseId `
            -ExpectedRunNonce $ExpectedRunNonce `
            -ExpectedRole ([string]$_.role) `
            -ExpectedPolicy ([string]$_.policy) `
            -ExpectedCommit $ExpectedCommit `
            -ExpectedEmuleSha256 $ExpectedEmuleSha256 `
            -ExpectedZipSha256 $ExpectedZipSha256 `
            -ExpectedManifestSha256 $ExpectedManifestSha256)
    })
    $provenProduct = @($valid | Where-Object {
        [string]$_.status -ceq 'PRODUCT_INVARIANT' -and
        @($_.proofs | Where-Object {
            -not $trustedBindings.Contains(
                [string]$_.binding_sha256
            )
        }).Count -eq 0
    })
    $untrustedProduct = @($valid | Where-Object {
        [string]$_.status -ceq 'PRODUCT_INVARIANT' -and
        @($_.proofs | Where-Object {
            -not $trustedBindings.Contains(
                [string]$_.binding_sha256
            )
        }).Count -gt 0
    })
    $labIncidents = @($valid | Where-Object {
        [string]$_.status -ceq 'LAB_BLOCKED'
    })
    $status = if ($provenProduct.Count -gt 0) {
        'FAIL'
    } elseif ($FixtureComplete -and $BothPoliciesPass -and
        $EvidenceComplete -and $CleanupComplete -and
        $labIncidents.Count -eq 0 -and
        $untrustedProduct.Count -eq 0 -and
        $valid.Count -eq @($FailureRecords).Count) {
        'PASS'
    } else { 'BLOCKED' }
    return [pscustomobject][ordered]@{
        formal_status = $status
        proven_product_failure_count = $provenProduct.Count
        untrusted_product_failure_count = $untrustedProduct.Count
        lab_incident_count = $labIncidents.Count
        malformed_or_stale_failure_count =
            @($FailureRecords).Count - $valid.Count
    }
}

function Test-I03PersistedFailureSources {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()][object[]]$Manifest,
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$ExpectedCaseId,
        [Parameter(Mandatory = $true)][string]$ExpectedRunNonce,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Coordinator', 'Peer')][string]$ExpectedRole
    )

    $rootPath = Get-LabFullPath -Path $Root
    $rootPrefix = $rootPath.TrimEnd('\') + '\'
    $hashes = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    $bindingHashes = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    $bindings = [System.Collections.Generic.List[object]]::new()
    $productCodes = @(
        'CANDIDATE_EXITED', 'UI_UNRESPONSIVE',
        'API_UNAVAILABLE', 'API_CONTRACT', 'LINK_REJECTED',
        'IPV4_PREWARM_INVARIANT', 'PEER_IDENTITY_CHANGED',
        'NO_ROUTE', 'WRONG_FAMILY', 'DUPLICATE_ROUTE',
        'WRONG_OR_NONPHYSICAL_SOCKET',
        'CANDIDATE_THIRD_PARTY_SOCKET'
    )
    try {
        foreach ($entry in $Manifest) {
            if ($null -eq $entry) {
                throw 'MANIFEST_ENTRY_NULL'
            }
            $names = @($entry.PSObject.Properties.Name)
            if ($names.Count -ne 3 -or
                @('file_name', 'sha256', 'bytes' | Where-Object {
                    $names -cnotcontains $_
                }).Count -gt 0 -or
                [string]$entry.sha256 -notmatch '^[0-9a-f]{64}$' -or
                [Int64]$entry.bytes -le 0) {
                throw 'MANIFEST_ENTRY_INVALID'
            }
            $namePattern = if ($ExpectedRole -ceq 'Peer') {
                '^peer-failure-source-[0-9]{3}\.json$'
            } else { '^failure-source-[0-9]{3}\.json$' }
            if ([string]$entry.file_name -cnotmatch $namePattern) {
                throw 'FILE_NAME_INVALID'
            }
            $path = Get-LabFullPath -Path (
                Join-Path $rootPath ([string]$entry.file_name)
            )
            if (-not ($path.StartsWith(
                    $rootPrefix,
                    [StringComparison]::OrdinalIgnoreCase
                )) -or
                -not (Test-Path -LiteralPath $path -PathType Leaf)) {
                throw 'SOURCE_PATH_INVALID'
            }
            $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if (($item.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                [Int64]$item.Length -ne [Int64]$entry.bytes -or
                (Get-LabSha256 -Path $path) -cne [string]$entry.sha256) {
                throw 'SOURCE_BYTES_INVALID'
            }
            $source = Get-Content -LiteralPath $path -Raw `
                -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $sourceNames = @($source.PSObject.Properties.Name)
            if ($sourceNames.Count -ne 8 -or
                @(
                    'schema', 'case_id', 'run_nonce', 'role',
                    'policy', 'phase', 'code', 'evidence' |
                        Where-Object { $sourceNames -cnotcontains $_ }
                ).Count -gt 0 -or
                [string]$source.schema -cne
                    'ese.v91.i03-failure-source/v1' -or
                [string]$source.case_id -cne $ExpectedCaseId -or
                [string]$source.run_nonce -cne $ExpectedRunNonce -or
                [string]$source.role -cne $ExpectedRole -or
                [string]$source.policy -cnotin @(
                    'none', 'auto', 'preferred'
                ) -or
                -not (Test-I03FailurePhase -Phase $source.phase) -or
                $source.code -isnot [string] -or
                [string]$source.code -cnotin $productCodes) {
                throw 'SOURCE_SCHEMA_INVALID'
            }
            $sourceHash = [string]$entry.sha256
            if (-not $hashes.Add($sourceHash)) {
                throw 'SOURCE_HASH_DUPLICATE'
            }
            $kind = ([string]$source.code).ToLowerInvariant()
            $bindingInput = '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f
                [string]$source.case_id, [string]$source.run_nonce,
                [string]$source.role, [string]$source.policy,
                [string]$source.phase, $kind, $sourceHash
            $bindingHash = Get-LabStringSha256 -Value $bindingInput
            if (-not $bindingHashes.Add($bindingHash)) {
                throw 'SOURCE_BINDING_DUPLICATE'
            }
            $bindings.Add([pscustomobject][ordered]@{
                source_sha256 = $sourceHash
                role = [string]$source.role
                policy = [string]$source.policy
                phase = [string]$source.phase
                code = [string]$source.code
                kind = $kind
                binding_sha256 = $bindingHash
            })
        }
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-failure-source-verification/v1'
            ok = $true
            error_code = 'NONE'
            verified_count = $hashes.Count
            source_sha256 = @($hashes)
            trusted_binding_sha256 = @($bindingHashes)
            source_bindings = @($bindings)
        }
    } catch {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-failure-source-verification/v1'
            ok = $false
            error_code = 'FAILURE_SOURCE_INVALID'
            verified_count = 0
            source_sha256 = @()
            trusted_binding_sha256 = @()
            source_bindings = @()
        }
    }
}

function Get-I03ClockEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$T0CoordinatorSendUtc,
        [Parameter(Mandatory = $true)][string]$T0CoordinatorEchoUtc,
        [Parameter(Mandatory = $true)][string]$T1PeerReceiveUtc,
        [Parameter(Mandatory = $true)][string]$T2PeerSendUtc,
        [Parameter(Mandatory = $true)][string]$T3CoordinatorReceiveUtc
    )

    $values = @(
        $T0CoordinatorSendUtc, $T0CoordinatorEchoUtc,
        $T1PeerReceiveUtc, $T2PeerSendUtc, $T3CoordinatorReceiveUtc
    )
    $parsed = [System.Collections.Generic.List[DateTime]]::new()
    foreach ($value in $values) {
        $timestamp = [DateTime]::MinValue
        if ($value -notmatch
                '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$' -or
            -not [DateTime]::TryParseExact(
                $value, 'o', [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind,
                [ref]$timestamp
            ) -or $timestamp.Kind -ne [DateTimeKind]::Utc) {
            return [pscustomobject][ordered]@{
                schema = 'ese.v91.i03-clock-evidence/v1'
                collector_ok = $false
                collector_error_code = 'CLOCK_TIMESTAMP_INVALID'
                certified_within_1000_ms = $false
            }
        }
        $parsed.Add($timestamp)
    }
    $t0 = $parsed[0]
    $t0Echo = $parsed[1]
    $t1 = $parsed[2]
    $t2 = $parsed[3]
    $t3 = $parsed[4]
    if ($T0CoordinatorEchoUtc -cne $T0CoordinatorSendUtc -or
        $t0Echo -ne $t0 -or $t3 -lt $t0 -or $t2 -lt $t1) {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-clock-evidence/v1'
            collector_ok = $false
            collector_error_code = 'CLOCK_ORDER_OR_ECHO_INVALID'
            certified_within_1000_ms = $false
        }
    }
    $delayMs = ($t3 - $t0).TotalMilliseconds -
        ($t2 - $t1).TotalMilliseconds
    $offsetMs = (($t1 - $t0).TotalMilliseconds +
        ($t2 - $t3).TotalMilliseconds) / 2.0
    if ($delayMs -lt 0) {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-clock-evidence/v1'
            collector_ok = $false
            collector_error_code = 'CLOCK_NEGATIVE_DELAY'
            certified_within_1000_ms = $false
        }
    }
    $uncertaintyMs = $delayMs / 2.0
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-clock-evidence/v1'
        collector_ok = $true
        collector_error_code = 'NONE'
        method = 'four-timestamp shared-coordination challenge'
        t0_coordinator_send_utc = $T0CoordinatorSendUtc
        t1_peer_receive_utc = $T1PeerReceiveUtc
        t2_peer_send_utc = $T2PeerSendUtc
        t3_coordinator_receive_utc = $T3CoordinatorReceiveUtc
        round_trip_delay_ms = [Math]::Round($delayMs, 3)
        estimated_offset_ms = [Math]::Round($offsetMs, 3)
        uncertainty_ms = [Math]::Round($uncertaintyMs, 3)
        certified_within_1000_ms =
            [Math]::Abs($offsetMs) + $uncertaintyMs -le 1000.0
    }
}

function Get-I03TopologyDecision {
    param(
        [Parameter(Mandatory = $true)][bool]$DifferentMachineIdentities,
        [Parameter(Mandatory = $true)][bool]$SameIPv4PhysicalPrefix,
        [Parameter(Mandatory = $true)][bool]$SameIPv6PhysicalPrefix,
        [Parameter(Mandatory = $true)][bool]$IPv6OnLink,
        [Parameter(Mandatory = $true)][bool]$NativeIPv4,
        [Parameter(Mandatory = $true)][bool]$NativeIPv6,
        [Parameter(Mandatory = $true)][bool]$PhysicalSingleAdapter,
        [Parameter(Mandatory = $true)][bool]$OverlayDetected,
        [Parameter(Mandatory = $true)][bool]$RoutedNativeIPv6
    )

    $baseValid = $DifferentMachineIdentities -and $NativeIPv4 -and
        $NativeIPv6 -and $PhysicalSingleAdapter -and -not $OverlayDetected
    $t1 = $baseValid -and $SameIPv4PhysicalPrefix -and
        $SameIPv6PhysicalPrefix -and $IPv6OnLink
    $t2 = $baseValid -and -not $t1 -and $RoutedNativeIPv6
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-topology-decision/v1'
        status = if ($t1 -or $t2) { 'PASS' } else { 'LAB_BLOCKED' }
        code = if ($t1 -or $t2) { 'NONE' } else { 'TOPOLOGY' }
        topology_class = if ($t1) { 'T1' } elseif ($t2) { 'T2' } else { '' }
        t1_proved = $t1
        t2_proved = $t2
    }
}

function Get-I03RouteSelectionDecision {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('auto', 'preferred')][string]$Policy,
        [Parameter(Mandatory = $true)][bool]$CollectorOk,
        [Parameter(Mandatory = $true)][bool]$FixtureCertified,
        [AllowNull()][AllowEmptyCollection()][object[]]$Rows = @(),
        [AllowNull()][AllowEmptyCollection()][object[]]$SocketProofs = @(),
        [Parameter(Mandatory = $true)][double]$StableSeconds,
        [Parameter(Mandatory = $true)][bool]$Contamination,
        [bool]$AmbiguousSelection = $false,
        [bool]$WrongFamilyObserved = $false,
        [ValidateRange(0, 60)][double]$RequiredStableSeconds = 5
    )

    if ($null -eq $Rows) { $Rows = @() }
    if ($null -eq $SocketProofs) { $SocketProofs = @() }
    $result = [ordered]@{
        schema = 'ese.v91.i03-route-decision/v1'
        status = 'LAB_BLOCKED'
        code = 'EVIDENCE_INCOMPLETE'
        expected_family = if ($Policy -ceq 'auto') { 'IPv4' } else { 'IPv6' }
        product_match = $false
    }
    if (-not $CollectorOk) {
        $result.code = 'COLLECTOR_UNAVAILABLE'
        return [pscustomobject]$result
    }
    if (-not $FixtureCertified) { return [pscustomobject]$result }
    if ($Contamination) {
        $result.code = 'EXTERNAL_CONTAMINATION'
        return [pscustomobject]$result
    }
    if ($AmbiguousSelection) {
        $result.status = 'PRODUCT_INVARIANT'
        $result.code = 'DUPLICATE_ROUTE'
        return [pscustomobject]$result
    }
    if ($WrongFamilyObserved) {
        $result.status = 'PRODUCT_INVARIANT'
        $result.code = 'WRONG_FAMILY'
        return [pscustomobject]$result
    }
    if (@($SocketProofs | Where-Object {
                $null -eq $_ -or -not [bool]$_.collector_ok
            }).Count -gt 0) {
        $result.code = 'COLLECTOR_AMBIGUOUS'
        return [pscustomobject]$result
    }
    if ($Rows.Count -eq 0) {
        $result.status = 'PRODUCT_INVARIANT'
        $result.code = 'NO_ROUTE'
        return [pscustomobject]$result
    }
    if ($Rows.Count -gt 1) {
        $result.status = 'PRODUCT_INVARIANT'
        $result.code = 'DUPLICATE_ROUTE'
        return [pscustomobject]$result
    }
    if ([string]$Rows[0].family -cne [string]$result.expected_family) {
        $result.status = 'PRODUCT_INVARIANT'
        $result.code = 'WRONG_FAMILY'
        return [pscustomobject]$result
    }
    if ($SocketProofs.Count -ne 1 -or
        -not [bool]$SocketProofs[0].pid_matches -or
        -not [bool]$SocketProofs[0].tuple_current_exact -or
        -not [bool]$SocketProofs[0].local_address_assigned -or
        -not [bool]$SocketProofs[0].physical_nonvirtual -or
        ($SocketProofs[0].PSObject.Properties.Name -ccontains
            'attribution_exact' -and
            -not [bool]$SocketProofs[0].attribution_exact)) {
        $result.status = 'PRODUCT_INVARIANT'
        $result.code = 'WRONG_OR_NONPHYSICAL_SOCKET'
        return [pscustomobject]$result
    }
    if ($StableSeconds -lt $RequiredStableSeconds) {
        $result.status = 'PRODUCT_INVARIANT'
        $result.code = 'NO_ROUTE'
        return [pscustomobject]$result
    }
    $result.status = 'PASS'
    $result.code = 'NONE'
    $result.product_match = $true
    return [pscustomobject]$result
}

function Add-I03JsonLine {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )

    Add-Content -LiteralPath $Path `
        -Value ($Value | ConvertTo-Json -Depth 32 -Compress) -Encoding utf8
}

function Wait-I03JsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [AllowEmptyString()][string]$StopPath = ''
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ($StopPath -and
            (Test-Path -LiteralPath $StopPath -PathType Leaf)) {
            return [pscustomobject]@{
                kind = 'stop'
                value = Get-Content -LiteralPath $StopPath -Raw |
                    ConvertFrom-Json -ErrorAction Stop
            }
        }
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            return [pscustomobject]@{
                kind = 'value'
                value = Get-Content -LiteralPath $Path -Raw |
                    ConvertFrom-Json -ErrorAction Stop
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    return $null
}

function Get-I03AdapterEvidence {
    param(
        [Parameter(Mandatory = $true)][int]$InterfaceIndex,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $adapter = Get-NetAdapter -InterfaceIndex $InterfaceIndex `
        -ErrorAction Stop
    $overlayPattern =
        '(?i)tailscale|wireguard|cloudflare|warp|zerotier|openvpn|' +
        'hyper-v|vethernet|loopback|tunnel|tap|vpn|hamachi|teredo|' +
        '6to4|isatap|ip[- ]?https|vmware|virtualbox|vbox|' +
        'parallels|qemu|virtio|xen'
    $overlayLike = ([string]$adapter.Name) -match $overlayPattern -or
        ([string]$adapter.InterfaceDescription) -match $overlayPattern
    $physical = [bool]$adapter.HardwareInterface -and
        -not [bool]$adapter.Virtual -and -not $overlayLike -and
        [string]$adapter.Status -eq 'Up'
    return [pscustomobject][ordered]@{
        context = $Context
        interface_index = [int]$adapter.InterfaceIndex
        interface_id = Get-LabInterfaceId `
            -Id ([string]$adapter.InterfaceGuid) `
            -Name ([string]$adapter.Name) `
            -Description ([string]$adapter.InterfaceDescription)
        status = [string]$adapter.Status
        hardware_interface = [bool]$adapter.HardwareInterface
        virtual = [bool]$adapter.Virtual
        overlay_like = $overlayLike
        physical_nonvirtual = $physical
    }
}

function Get-I03AssignedAddress {
    param(
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)]
        [Net.Sockets.AddressFamily]$Family,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $familyName = if ($Family -eq
        [Net.Sockets.AddressFamily]::InterNetwork) { 'IPv4' } else { 'IPv6' }
    $item = Get-NetIPAddress -AddressFamily $familyName `
        -ErrorAction Stop | Where-Object {
            (Get-I03NormalizedIp -Address ([string]$_.IPAddress)) -eq
                (Get-I03NormalizedIp -Address $Address) -and
            [string]$_.AddressState -eq 'Preferred'
        } | Select-Object -First 1
    if ($null -eq $item) {
        throw "$Context is not a Preferred address assigned on this host"
    }
    $adapter = Get-I03AdapterEvidence `
        -InterfaceIndex ([int]$item.InterfaceIndex) -Context $Context
    return [pscustomobject][ordered]@{
        address = Get-I03NormalizedIp -Address ([string]$item.IPAddress)
        address_class = Get-I03NativeAddressClass `
            -Address ([string]$item.IPAddress)
        interface_index = [int]$item.InterfaceIndex
        prefix_length = [int]$item.PrefixLength
        adapter = $adapter
    }
}

function Get-I03RouteEvidence {
    param([Parameter(Mandatory = $true)][string]$RemoteAddress)

    try {
        $route = Find-NetRoute -RemoteIPAddress $RemoteAddress `
            -ErrorAction Stop | Select-Object -First 1
        if ($null -eq $route) { throw 'Find-NetRoute returned no route' }
        $source = Get-I03NormalizedIp -Address ([string]$route.IPAddress)
        $adapter = Get-I03AdapterEvidence `
            -InterfaceIndex ([int]$route.InterfaceIndex) `
            -Context "route-to-$RemoteAddress"
        return [pscustomobject][ordered]@{
            available = $true
            family = if ($RemoteAddress.Contains(':')) { 'IPv6' } else { 'IPv4' }
            remote_address = Get-I03NormalizedIp -Address $RemoteAddress
            remote_class = Get-I03NativeAddressClass `
                -Address $RemoteAddress
            source_address = $source
            source_class = Get-I03NativeAddressClass -Address $source
            interface_index = [int]$route.InterfaceIndex
            next_hop_class = if ([string]$route.NextHop -in @(
                '0.0.0.0', '::'
            )) {
                'on-link'
            } else {
                Get-I03NativeAddressClass -Address ([string]$route.NextHop)
            }
            adapter = $adapter
            error = $null
        }
    } catch {
        return [pscustomobject][ordered]@{
            available = $false
            family = if ($RemoteAddress.Contains(':')) { 'IPv6' } else { 'IPv4' }
            remote_address = Get-I03NormalizedIp -Address $RemoteAddress
            remote_class = Get-I03NativeAddressClass `
                -Address $RemoteAddress
            source_address = ''
            source_class = 'invalid'
            interface_index = $null
            next_hop_class = 'unknown'
            adapter = $null
            error = $_.Exception.Message
        }
    }
}

function Test-I03SamePhysicalPrefix {
    param(
        [Parameter(Mandatory = $true)][string]$LeftAddress,
        [Parameter(Mandatory = $true)][int]$LeftPrefixLength,
        [Parameter(Mandatory = $true)][string]$RightAddress,
        [Parameter(Mandatory = $true)][int]$RightPrefixLength
    )

    $left = $null
    $right = $null
    if (-not [Net.IPAddress]::TryParse(
        $LeftAddress.Split('%')[0], [ref]$left) -or
        -not [Net.IPAddress]::TryParse(
            $RightAddress.Split('%')[0], [ref]$right) -or
        $left.AddressFamily -ne $right.AddressFamily -or
        $LeftPrefixLength -ne $RightPrefixLength) {
        return $false
    }
    $leftBytes = $left.GetAddressBytes()
    $rightBytes = $right.GetAddressBytes()
    $maxBits = $leftBytes.Length * 8
    if ($LeftPrefixLength -le 0 -or $LeftPrefixLength -gt $maxBits) {
        return $false
    }
    $wholeBytes = [Math]::Floor($LeftPrefixLength / 8)
    for ($index = 0; $index -lt $wholeBytes; $index++) {
        if ($leftBytes[$index] -ne $rightBytes[$index]) {
            return $false
        }
    }
    $remainingBits = $LeftPrefixLength % 8
    if ($remainingBits -gt 0) {
        $mask = (0xff -shl (8 - $remainingBits)) -band 0xff
        if (($leftBytes[$wholeBytes] -band $mask) -ne
            ($rightBytes[$wholeBytes] -band $mask)) {
            return $false
        }
    }
    return $true
}

function Get-I03TupleKey {
    param(
        [Parameter(Mandatory = $true)][string]$Family,
        [Parameter(Mandatory = $true)][string]$LocalAddress,
        [Parameter(Mandatory = $true)][int]$LocalPort,
        [Parameter(Mandatory = $true)][string]$RemoteAddress,
        [Parameter(Mandatory = $true)][int]$RemotePort
    )

    return '{0}|{1}|{2}|{3}|{4}' -f $Family,
        (Get-I03NormalizedIp -Address $LocalAddress), $LocalPort,
        (Get-I03NormalizedIp -Address $RemoteAddress), $RemotePort
}

function Get-I03TargetConnectionSnapshot {
    $capturedAt = Get-LabUtcTimestamp
    try {
        $rows = @(
            Get-NetTCPConnection -ErrorAction Stop | Where-Object {
                [int]$_.RemotePort -eq $PeerTcpPort -and
                (Get-I03NormalizedIp -Address ([string]$_.RemoteAddress)) -in
                    @($peerV4Text, $peerV6Text)
            } | ForEach-Object {
                $remote = Get-I03NormalizedIp -Address ([string]$_.RemoteAddress)
                $local = Get-I03NormalizedIp -Address ([string]$_.LocalAddress)
                $family = if ($remote.Contains(':')) { 'IPv6' } else { 'IPv4' }
                [pscustomobject][ordered]@{
                    captured_at_utc = Get-LabUtcTimestamp
                    owning_process = [int]$_.OwningProcess
                    state = [string]$_.State
                    family = $family
                    local_address = $local
                    local_port = [int]$_.LocalPort
                    remote_address = $remote
                    remote_port = [int]$_.RemotePort
                    tuple_key = Get-I03TupleKey -Family $family `
                        -LocalAddress $local -LocalPort ([int]$_.LocalPort) `
                        -RemoteAddress $remote -RemotePort ([int]$_.RemotePort)
                }
            }
        )
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-target-connection-collector/v1'
            ok = $true
            error_code = 'NONE'
            captured_at_utc = $capturedAt
            rows = $rows
        }
    } catch {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-target-connection-collector/v1'
            ok = $false
            error_code = 'TARGET_TCP_QUERY_FAILED'
            captured_at_utc = $capturedAt
            rows = @()
        }
    }
}

function Get-I03TargetConnections {
    $snapshot = Get-I03TargetConnectionSnapshot
    if (-not [bool]$snapshot.ok) {
        throw "I03_COLLECTOR::$($snapshot.error_code)"
    }
    return @($snapshot.rows)
}

function Get-I03ProcessSocketCensus {
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    try {
        $tcp = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object {
            [int]$_.OwningProcess -eq $ProcessId
        } | ForEach-Object {
            [pscustomobject][ordered]@{
                transport = 'TCP'
                state = [string]$_.State
                local_address = Get-I03NormalizedIp `
                    -Address ([string]$_.LocalAddress)
                local_port = [int]$_.LocalPort
                remote_address = Get-I03NormalizedIp `
                    -Address ([string]$_.RemoteAddress)
                remote_port = [int]$_.RemotePort
                owning_process = [int]$_.OwningProcess
            }
        })
        $udp = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object {
            [int]$_.OwningProcess -eq $ProcessId
        } | ForEach-Object {
            [pscustomobject][ordered]@{
                transport = 'UDP'
                state = 'Bound'
                local_address = Get-I03NormalizedIp `
                    -Address ([string]$_.LocalAddress)
                local_port = [int]$_.LocalPort
                remote_address = ''
                remote_port = 0
                owning_process = [int]$_.OwningProcess
            }
        })
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-process-socket-census/v1'
            collector_ok = $true
            collector_error_code = 'NONE'
            process_id = $ProcessId
            tcp_rows = $tcp
            udp_rows = $udp
            socket_count = $tcp.Count + $udp.Count
        }
    } catch {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-process-socket-census/v1'
            collector_ok = $false
            collector_error_code = 'PROCESS_SOCKET_QUERY_FAILED'
            process_id = $ProcessId
            tcp_rows = @()
            udp_rows = @()
            socket_count = 0
        }
    }
}

function Get-I03CandidateSocketCensusDecision {
    param(
        [Parameter(Mandatory = $true)][object]$Census,
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][int]$TcpPort,
        [Parameter(Mandatory = $true)][int]$UdpPort,
        [Parameter(Mandatory = $true)][int]$WebPort,
        [Parameter(Mandatory = $true)][string[]]$TargetAddresses,
        [Parameter(Mandatory = $true)][int]$TargetPort,
        [Parameter(Mandatory = $true)][string]$ControlAddress,
        [Parameter(Mandatory = $true)][int]$ControlPort
    )

    $censusShapeValid = [string]$Census.schema -ceq
            'ese.v91.i03-process-socket-census/v1' -and
        $Census.collector_ok -is [bool] -and
        (Test-I03StrictJsonInteger -Value $Census.process_id `
            -Expected $ProcessId) -and
        $Census.tcp_rows -is [System.Array] -and
        $Census.udp_rows -is [System.Array]
    if (-not $censusShapeValid -or -not [bool]$Census.collector_ok) {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-candidate-socket-decision/v1'
            collector_ok = $false
            collector_error_code = if (-not $censusShapeValid) {
                'INVALID_PROCESS_SOCKET_CENSUS'
            } elseif (
                [string]$Census.collector_error_code
            ) { [string]$Census.collector_error_code } else {
                'PROCESS_SOCKET_QUERY_FAILED'
            }
            process_id = $ProcessId
            allowed_row_count = 0
            unexpected_row_count = 0
            allowed_rows = @()
            unexpected_rows = @()
            complete = $false
        }
    }

    $targetSet = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($target in $TargetAddresses) {
        [void]$targetSet.Add((Get-I03NormalizedIp -Address $target))
    }
    $control = Get-I03NormalizedIp -Address $ControlAddress
    $allowed = [System.Collections.Generic.List[object]]::new()
    $unexpected = [System.Collections.Generic.List[object]]::new()

    foreach ($row in @($Census.tcp_rows)) {
        $local = Get-I03NormalizedIp -Address ([string]$row.local_address)
        $remote = Get-I03NormalizedIp -Address ([string]$row.remote_address)
        $state = [string]$row.state
        $localPort = [int]$row.local_port
        $remotePort = [int]$row.remote_port
        $reason = ''
        if ([int]$row.owning_process -ne $ProcessId) {
            $reason = 'wrong_process'
        } elseif ($state -eq 'Listen' -and
            $localPort -in @($TcpPort, $WebPort) -and
            $remotePort -eq 0) {
            $reason = 'owned_listener'
        } elseif ($targetSet.Contains($remote) -and
            $remotePort -eq $TargetPort) {
            $reason = 'controlled_peer_flow'
        } elseif ($remote -eq $control -and
            $remotePort -eq $ControlPort) {
            $reason = 'controlled_server_flow'
        } elseif ($localPort -eq $WebPort -and
            $remote -in @('127.0.0.1', '::1')) {
            $reason = 'local_api_probe'
        } else {
            $reason = 'tcp_not_allowlisted'
        }
        $classified = [pscustomobject][ordered]@{
            transport = 'TCP'
            state = $state
            local_address = $local
            local_port = $localPort
            remote_address = $remote
            remote_port = $remotePort
            owning_process = [int]$row.owning_process
            classification = $reason
        }
        if ($reason -in @(
                'owned_listener', 'controlled_peer_flow',
                'controlled_server_flow', 'local_api_probe'
            )) {
            $allowed.Add($classified)
        } else {
            $unexpected.Add($classified)
        }
    }
    foreach ($row in @($Census.udp_rows)) {
        $local = Get-I03NormalizedIp -Address ([string]$row.local_address)
        $isAllowed = [int]$row.owning_process -eq $ProcessId -and
            [string]$row.state -eq 'Bound' -and
            [int]$row.local_port -eq $UdpPort -and
            [int]$row.remote_port -eq 0
        $classified = [pscustomobject][ordered]@{
            transport = 'UDP'
            state = [string]$row.state
            local_address = $local
            local_port = [int]$row.local_port
            remote_address = [string]$row.remote_address
            remote_port = [int]$row.remote_port
            owning_process = [int]$row.owning_process
            classification = if ($isAllowed) {
                'owned_udp_endpoint'
            } else { 'udp_not_allowlisted' }
        }
        if ($isAllowed) {
            $allowed.Add($classified)
        } else {
            $unexpected.Add($classified)
        }
    }

    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-candidate-socket-decision/v1'
        collector_ok = $true
        collector_error_code = 'NONE'
        process_id = $ProcessId
        allowed_row_count = $allowed.Count
        unexpected_row_count = $unexpected.Count
        allowed_rows = @($allowed)
        unexpected_rows = @($unexpected)
        complete = $unexpected.Count -eq 0
    }
}

function Get-I03PeerInboundConnectionSnapshot {
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][int]$LocalPort
    )

    $census = Get-I03ProcessSocketCensus -ProcessId $ProcessId
    if (-not [bool]$census.collector_ok) {
        throw "I03_COLLECTOR::$($census.collector_error_code)"
    }
    return @($census.tcp_rows | Where-Object {
        [string]$_.state -eq 'Established' -and
        [int]$_.local_port -eq $LocalPort
    } | ForEach-Object {
        [pscustomobject][ordered]@{
            owning_process = [int]$_.owning_process
            local_address = Get-I03NormalizedIp `
                -Address ([string]$_.local_address)
            family = if ((Get-I03NormalizedIp -Address `
                    ([string]$_.local_address)).Contains(':')) {
                'IPv6'
            } else { 'IPv4' }
            local_port = [int]$_.local_port
            remote_address = Get-I03NormalizedIp `
                -Address ([string]$_.remote_address)
            remote_port = [int]$_.remote_port
        }
    })
}

function Get-I03EmuleProcessCensus {
    try {
        $rows = @(Get-CimInstance -ClassName Win32_Process `
            -Filter "Name = 'emule.exe'" -ErrorAction Stop |
            ForEach-Object {
                $path = [string]$_.ExecutablePath
                [pscustomobject][ordered]@{
                    process_id = [int]$_.ProcessId
                    executable_path = $path
                    executable_sha256 = if ($path -and
                        (Test-Path -LiteralPath $path -PathType Leaf)) {
                        Get-LabSha256 -Path $path
                    } else { '' }
                }
            })
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-emule-process-census/v1'
            collector_ok = $true
            collector_error_code = 'NONE'
            captured_at_utc = Get-LabUtcTimestamp
            process_count = $rows.Count
            rows = $rows
        }
    } catch {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-emule-process-census/v1'
            collector_ok = $false
            collector_error_code = 'EMULE_PROCESS_QUERY_FAILED'
            captured_at_utc = Get-LabUtcTimestamp
            process_count = 0
            rows = @()
        }
    }
}

function Get-I03TerminalSocketCleanupEvidence {
    param(
        [Parameter(Mandatory = $true)][int[]]$Ports,
        [AllowEmptyCollection()][int[]]$OwnedProcessIds = @()
    )

    try {
        $portSet = @($Ports | Sort-Object -Unique)
        $tcpAll = @(Get-NetTCPConnection -ErrorAction Stop)
        $udpAll = @(Get-NetUDPEndpoint -ErrorAction Stop)
        $tcpAtPorts = @($tcpAll | Where-Object {
            [int]$_.LocalPort -in $portSet
        } | ForEach-Object {
            [pscustomobject][ordered]@{
                state = [string]$_.State
                local_port = [int]$_.LocalPort
                owning_process = [int]$_.OwningProcess
            }
        })
        $udpAtPorts = @($udpAll | Where-Object {
            [int]$_.LocalPort -in $portSet
        } | ForEach-Object {
            [pscustomobject][ordered]@{
                local_port = [int]$_.LocalPort
                owning_process = [int]$_.OwningProcess
            }
        })
        $ownedPids = @($OwnedProcessIds | Sort-Object -Unique)
        $ownedTcp = @($tcpAll | Where-Object {
            [int]$_.OwningProcess -in $ownedPids
        })
        $ownedUdp = @($udpAll | Where-Object {
            [int]$_.OwningProcess -in $ownedPids
        })
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-terminal-socket-cleanup/v1'
            collector_ok = $true
            collector_error_code = 'NONE'
            checked_ports = $portSet
            checked_process_ids = $ownedPids
            tcp_port_row_count = $tcpAtPorts.Count
            udp_port_row_count = $udpAtPorts.Count
            owned_tcp_row_count = $ownedTcp.Count
            owned_udp_row_count = $ownedUdp.Count
            ports_free = $tcpAtPorts.Count -eq 0 -and
                $udpAtPorts.Count -eq 0
            owned_process_sockets_free = $ownedTcp.Count -eq 0 -and
                $ownedUdp.Count -eq 0
            complete = $tcpAtPorts.Count -eq 0 -and
                $udpAtPorts.Count -eq 0 -and
                $ownedTcp.Count -eq 0 -and $ownedUdp.Count -eq 0
        }
    } catch {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-terminal-socket-cleanup/v1'
            collector_ok = $false
            collector_error_code = 'TERMINAL_SOCKET_QUERY_FAILED'
            checked_ports = @($Ports | Sort-Object -Unique)
            checked_process_ids = @($OwnedProcessIds | Sort-Object -Unique)
            tcp_port_row_count = 0
            udp_port_row_count = 0
            owned_tcp_row_count = 0
            owned_udp_row_count = 0
            ports_free = $false
            owned_process_sockets_free = $false
            complete = $false
        }
    }
}

function Get-I03SocketEvidence {
    param(
        [Parameter(Mandatory = $true)][object]$Connection,
        [Parameter(Mandatory = $true)][int]$ExpectedProcessId
    )

    $assigned = $null
    $adapter = $null
    $currentMatches = @()
    $collectorOk = $false
    $collectorErrorCode = 'SOCKET_EVIDENCE_UNAVAILABLE'
    try {
        $familyName = if ([string]$Connection.family -eq 'IPv6') {
            'IPv6'
        } else { 'IPv4' }
        $assignedMatches = @(Get-NetIPAddress -AddressFamily $familyName `
            -ErrorAction Stop | Where-Object {
                (Get-I03NormalizedIp -Address ([string]$_.IPAddress)) -eq
                    (Get-I03NormalizedIp -Address ([string]$Connection.local_address))
            })
        if ($assignedMatches.Count -ne 1) {
            $collectorErrorCode = 'LOCAL_ADDRESS_ADAPTER_AMBIGUOUS'
        } else {
            $assigned = $assignedMatches[0]
            $adapter = Get-I03AdapterEvidence `
                -InterfaceIndex ([int]$assigned.InterfaceIndex) `
                -Context 'candidate-established-socket'
            $currentMatches = @(
                Get-NetTCPConnection -ErrorAction Stop | Where-Object {
                    [string]$_.State -eq 'Established' -and
                    [int]$_.OwningProcess -eq $ExpectedProcessId -and
                    [int]$_.LocalPort -eq [int]$Connection.local_port -and
                    [int]$_.RemotePort -eq [int]$Connection.remote_port -and
                    (Get-I03NormalizedIp `
                        -Address ([string]$_.LocalAddress)) -eq
                            (Get-I03NormalizedIp -Address `
                                ([string]$Connection.local_address)) -and
                    (Get-I03NormalizedIp `
                        -Address ([string]$_.RemoteAddress)) -eq
                            (Get-I03NormalizedIp -Address `
                                ([string]$Connection.remote_address))
                    }
            )
            if ($currentMatches.Count -le 1) {
                $collectorOk = $true
                $collectorErrorCode = 'NONE'
            } else {
                $collectorErrorCode = 'CURRENT_TUPLE_AMBIGUOUS'
            }
        }
    } catch {
        $collectorOk = $false
        $collectorErrorCode = 'SOCKET_QUERY_FAILED'
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-socket-evidence/v2'
        collector_ok = $collectorOk
        collector_error_code = $collectorErrorCode
        connection = $Connection
        expected_process_id = $ExpectedProcessId
        pid_matches = [int]$Connection.owning_process -eq $ExpectedProcessId
        current_established_match_count = $currentMatches.Count
        tuple_current_exact = $collectorOk -and
            $currentMatches.Count -eq 1
        local_address_assigned = $null -ne $assigned
        local_address_class = Get-I03NativeAddressClass `
            -Address ([string]$Connection.local_address)
        adapter = $adapter
        physical_nonvirtual = $null -ne $adapter -and
            [bool]$adapter.physical_nonvirtual
    }
}

function Open-I03TcpProbe {
    param(
        [Parameter(Mandatory = $true)][Net.IPAddress]$Address,
        [Parameter(Mandatory = $true)][int]$Port,
        [ValidateRange(1, 30)][int]$TimeoutSeconds = 10
    )

    $client = New-Object Net.Sockets.TcpClient($Address.AddressFamily)
    try {
        if ($Address.AddressFamily -eq
            [Net.Sockets.AddressFamily]::InterNetworkV6) {
            $client.Client.DualMode = $false
        }
        $async = $client.BeginConnect($Address, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(
            [TimeSpan]::FromSeconds($TimeoutSeconds)
        )) {
            throw "Timed out connecting to $Address`:$Port"
        }
        $client.EndConnect($async)
        $local = [Net.IPEndPoint]$client.Client.LocalEndPoint
        $remote = [Net.IPEndPoint]$client.Client.RemoteEndPoint
        $localText = Get-I03NormalizedIp -Address $local.Address.ToString()
        $family = if ($Address.AddressFamily -eq
            [Net.Sockets.AddressFamily]::InterNetworkV6) { 'IPv6' } else {
            'IPv4'
        }
        $assigned = Get-I03AssignedAddress -Address $localText `
            -Family $Address.AddressFamily -Context "baseline-$family-source"
        return [pscustomobject][ordered]@{
            client = $client
            evidence = [pscustomobject][ordered]@{
                connected = $true
                connected_at_utc = Get-LabUtcTimestamp
                family = $family
                local_address = $localText
                local_port = [int]$local.Port
                remote_address = Get-I03NormalizedIp `
                    -Address $remote.Address.ToString()
                remote_port = [int]$remote.Port
                adapter = $assigned.adapter
            }
        }
    } catch {
        $client.Dispose()
        throw
    }
}

function Wait-I03Api {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process
    )

    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "eMule exited before API readiness (exit $($Process.ExitCode))"
        }
        try {
            $data = Invoke-RestMethod `
                -Uri "http://127.0.0.1:$Port/api/status" -TimeoutSec 2
            return $data
        } catch {
            Start-Sleep -Milliseconds 300
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "API on port $Port did not become ready"
}

function Wait-I03Listener {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [switch]$RequireDualStack
    )

    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "eMule exited before listener $Port became ready"
        }
        $census = Get-I03ProcessSocketCensus -ProcessId $Process.Id
        if (-not [bool]$census.collector_ok) {
            throw "I03_COLLECTOR::$($census.collector_error_code)"
        }
        $listeners = @($census.tcp_rows | Where-Object {
            [string]$_.state -eq 'Listen' -and
            [int]$_.local_port -eq $Port
        })
        if ($listeners.Count -gt 0) {
            $dual = @($listeners | Where-Object {
                (Get-I03NormalizedIp -Address `
                    ([string]$_.local_address)) -eq '::'
            }).Count -gt 0
            if (-not $RequireDualStack -or $dual) {
                return [pscustomobject][ordered]@{
                    listeners = $listeners
                    dual_stack = $dual
                }
            }
        }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($RequireDualStack) {
        throw "A dual-stack [::]:$Port listener did not become ready"
    }
    throw "Listener $Port did not become ready"
}

function Test-I03StrictJsonInteger {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][Int64]$Expected
    )

    if ($null -eq $Value -or $Value -is [bool] -or
        $Value -isnot [sbyte] -and $Value -isnot [byte] -and
        $Value -isnot [int16] -and $Value -isnot [uint16] -and
        $Value -isnot [int32] -and $Value -isnot [uint32] -and
        $Value -isnot [int64] -and $Value -isnot [uint64]) {
        return $false
    }
    try { return [Int64]$Value -eq $Expected } catch { return $false }
}

function Test-I03ApiIsolation {
    param(
        [AllowNull()][object]$Data,
        [switch]$AllowControlledEd2k
    )

    if ($null -eq $Data) { return $false }
    $names = @($Data.PSObject.Properties.Name)
    $booleanFalse = @(
        'upnp_critical_error', 'utp_hole_punch_enabled',
        'web_upnp_active', 'kad_connected', 'kad2_running',
        'kad2_connected', 'kad6_running', 'kad6_connected',
        'netlab_enabled', 'keepalive_running'
    )
    $integerZero = @('kad_configured_mask', 'kad_running_mask')
    $consents = @(
        'netlab_consent', 'netlab_advanced_consent',
        'netlab_contribution_consent'
    )
    foreach ($required in @(
        $booleanFalse + $integerZero + $consents +
        @('ed2k_connected', 'upnp_ports_forwarded')
    )) {
        if ($names -notcontains $required) { return $false }
    }
    foreach ($name in $booleanFalse) {
        if ($Data.$name -isnot [bool] -or $Data.$name -cne $false) {
            return $false
        }
    }
    foreach ($name in $integerZero) {
        if (-not (Test-I03StrictJsonInteger -Value $Data.$name `
                -Expected 0)) { return $false }
    }
    foreach ($name in $consents) {
        if ($Data.$name -isnot [string] -or
            [string]$Data.$name -cne 'declined') { return $false }
    }
    if ($Data.ed2k_connected -isnot [bool] -or
        $Data.upnp_ports_forwarded -isnot [string] -or
        [string]$Data.upnp_ports_forwarded -cnotin @(
            'false', 'unknown'
        )) {
        return $false
    }
    $ed2kStateValid = if ($AllowControlledEd2k) {
        $Data.ed2k_connected -ceq $true
    } else {
        $Data.ed2k_connected -ceq $false
    }
    return $ed2kStateValid
}

function Get-I03ApiEvidenceProjection {
    param(
        [AllowNull()][object]$Data,
        [Parameter(Mandatory = $true)][Int64]$DurationMs,
        [switch]$AllowControlledEd2k,
        [switch]$RequestFailed
    )

    $available = $null -ne $Data -and -not $RequestFailed
    $contractValid = $available -and
        (Test-I03ApiIsolation -Data $Data `
            -AllowControlledEd2k:$AllowControlledEd2k)
    $safeScalars = [ordered]@{}
    $safeHash = ''
    if ($contractValid) {
        $safeScalars = [ordered]@{
            upnp_critical_error = [bool]$Data.upnp_critical_error
            utp_hole_punch_enabled = [bool]$Data.utp_hole_punch_enabled
            web_upnp_active = [bool]$Data.web_upnp_active
            upnp_ports_forwarded = [string]$Data.upnp_ports_forwarded
            kad_connected = [bool]$Data.kad_connected
            kad_configured_mask = [int]$Data.kad_configured_mask
            netlab_enabled = [bool]$Data.netlab_enabled
            netlab_consent = [string]$Data.netlab_consent
            netlab_advanced_consent =
                [string]$Data.netlab_advanced_consent
            netlab_contribution_consent =
                [string]$Data.netlab_contribution_consent
            kad_running_mask = [int]$Data.kad_running_mask
            kad2_running = [bool]$Data.kad2_running
            kad2_connected = [bool]$Data.kad2_connected
            kad6_running = [bool]$Data.kad6_running
            kad6_connected = [bool]$Data.kad6_connected
            ed2k_connected = [bool]$Data.ed2k_connected
            keepalive_running = [bool]$Data.keepalive_running
        }
        $canonical = $safeScalars | ConvertTo-Json -Compress
        $safeHash = Get-LabStringSha256 -Value $canonical
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-api-status-evidence/v2'
        captured_at_utc = Get-LabUtcTimestamp
        available = $available
        duration_ms = $DurationMs
        contract_valid = $contractValid
        isolation_valid = $contractValid
        controlled_ed2k_expected = [bool]$AllowControlledEd2k
        error_code = if ($available) {
            if ($contractValid) { 'NONE' } else { 'API_CONTRACT_INVALID' }
        } else { 'API_UNAVAILABLE' }
        safe_scalars = $safeScalars
        safe_response_sha256 = $safeHash
    }
}

function Get-I03ApiProbe {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [switch]$AllowControlledEd2k
    )

    $watch = [Diagnostics.Stopwatch]::StartNew()
    $data = $null
    $requestFailed = $false
    try {
        $data = Invoke-RestMethod `
            -Uri "http://127.0.0.1:$Port/api/status" -TimeoutSec 2
    } catch {
        $requestFailed = $true
    } finally {
        $watch.Stop()
    }
    return Get-I03ApiEvidenceProjection -Data $data `
        -DurationMs ([Int64]$watch.ElapsedMilliseconds) `
        -AllowControlledEd2k:$AllowControlledEd2k `
        -RequestFailed:$requestFailed
}

function Initialize-I03UiProbe {
    if ('V91I03UiProbe' -as [type]) { return }
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class V91I03UiProbe {
    [DllImport("user32.dll", SetLastError=true)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam,
        uint flags, uint timeout, out IntPtr result);
}
'@
}

function Get-I03UiProbe {
    param([Parameter(Mandatory = $true)][Diagnostics.Process]$Process)

    Initialize-I03UiProbe
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $present = $false
    $responsive = $false
    try {
        $Process.Refresh()
        if (-not $Process.HasExited -and
            $Process.MainWindowHandle -ne [IntPtr]::Zero) {
            $present = $true
            $result = [IntPtr]::Zero
            $sent = [V91I03UiProbe]::SendMessageTimeout(
                $Process.MainWindowHandle, 0x0000,
                [IntPtr]::Zero, [IntPtr]::Zero,
                2, 500, [ref]$result
            )
            $responsive = $sent -ne [IntPtr]::Zero
        }
    } catch {
        $responsive = $false
    } finally {
        $watch.Stop()
    }
    return [pscustomobject][ordered]@{
        captured_at_utc = Get-LabUtcTimestamp
        process_id = $Process.Id
        main_window_present = $present
        message_pump_responsive = $responsive
        duration_ms = [Int64]$watch.ElapsedMilliseconds
    }
}

function Get-I03ProcessIdentity {
    param([Parameter(Mandatory = $true)][Diagnostics.Process]$Process)

    try {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw 'I03_PRODUCT_RUNTIME::PROCESS_EXITED_BEFORE_IDENTITY'
        }
        $path = [IO.Path]::GetFullPath([string]$Process.Path)
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-process-identity/v1'
            process_id = [int]$Process.Id
            start_time_utc = $Process.StartTime.ToUniversalTime().ToString('o')
            executable_path_sha256 = Get-LabStringSha256 -Value $path
            executable_sha256 = Get-LabSha256 -Path $path
        }
    } catch {
        if ([string]$_.Exception.Message -eq
            'I03_PRODUCT_RUNTIME::PROCESS_EXITED_BEFORE_IDENTITY') {
            throw
        }
        $exited = $false
        try {
            $Process.Refresh()
            $exited = [bool]$Process.HasExited
        } catch { $exited = $true }
        if ($exited) {
            throw 'I03_PRODUCT_RUNTIME::PROCESS_EXITED_BEFORE_IDENTITY'
        }
        throw 'I03_COLLECTOR::PROCESS_IDENTITY_QUERY_FAILED'
    }
}

function Test-I03ProcessIdentityMatch {
    param(
        [AllowNull()][object]$Expected,
        [AllowNull()][object]$Actual
    )

    if ($null -eq $Expected -or $null -eq $Actual) { return $false }
    $required = @(
        'schema', 'process_id', 'start_time_utc',
        'executable_path_sha256', 'executable_sha256'
    )
    try {
        foreach ($identity in @($Expected, $Actual)) {
            $names = @($identity.PSObject.Properties.Name)
            if ($names.Count -ne $required.Count -or
                @($required | Where-Object {
                    $names -cnotcontains $_
                }).Count -gt 0 -or
                $identity.schema -isnot [string] -or
                $identity.start_time_utc -isnot [string] -or
                $identity.executable_path_sha256 -isnot [string] -or
                $identity.executable_sha256 -isnot [string] -or
                [string]$identity.schema -cne
                    'ese.v91.i03-process-identity/v1' -or
                $identity.process_id -isnot [int] -or
                [int]$identity.process_id -le 0 -or
                [string]$identity.start_time_utc -notmatch
                    '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$' -or
                [string]$identity.executable_path_sha256 -notmatch
                    '^[0-9a-f]{64}$' -or
                [string]$identity.executable_sha256 -notmatch
                    '^[0-9a-f]{64}$') {
                return $false
            }
            $parsed = [DateTime]::MinValue
            if (-not [DateTime]::TryParseExact(
                    [string]$identity.start_time_utc,
                    'o', [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::RoundtripKind,
                    [ref]$parsed
                ) -or $parsed.Kind -ne [DateTimeKind]::Utc) {
                return $false
            }
        }
        return [int]$Expected.process_id -eq [int]$Actual.process_id -and
            [string]$Expected.start_time_utc -ceq
                [string]$Actual.start_time_utc -and
            [string]$Expected.executable_path_sha256 -ceq
                [string]$Actual.executable_path_sha256 -and
            [string]$Expected.executable_sha256 -ceq
                [string]$Actual.executable_sha256
    } catch { return $false }
}

function ConvertTo-I03RegistryDataProjection {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][string]$Kind
    )

    if ($null -eq $Value) { return $null }
    if ($Kind -ceq 'Binary') {
        return [Convert]::ToBase64String([byte[]]$Value)
    }
    if ($Kind -ceq 'MultiString') { return @([string[]]$Value) }
    return $Value
}

function Get-I03RegistryValueState {
    param(
        [Parameter(Mandatory = $true)][string]$SubKey,
        [Parameter(Mandatory = $true)][string]$ValueName
    )

    $base = [Microsoft.Win32.Registry]::CurrentUser
    $key = $base.OpenSubKey($SubKey, $false)
    try {
        $keyExists = $null -ne $key
        $valueExists = $keyExists -and @($key.GetValueNames()) -contains
            $ValueName
        $kind = ''
        $data = $null
        if ($valueExists) {
            $kind = $key.GetValueKind($ValueName).ToString()
            $data = ConvertTo-I03RegistryDataProjection `
                -Value ($key.GetValue($ValueName, $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)) `
                -Kind $kind
        }
        $state = [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-registry-value-state/v1'
            subkey_sha256 = Get-LabStringSha256 -Value $SubKey
            value_name_sha256 = Get-LabStringSha256 -Value $ValueName
            key_exists = $keyExists
            value_exists = $valueExists
            kind = $kind
            data = $data
        }
        $state | Add-Member -NotePropertyName state_sha256 `
            -NotePropertyValue (Get-LabStringSha256 -Value (
                $state | ConvertTo-Json -Depth 16 -Compress))
        return $state
    } finally {
        if ($null -ne $key) { $key.Dispose() }
    }
}

function Get-I03RegistryTreeState {
    param([Parameter(Mandatory = $true)][string]$SubKey)

    $base = [Microsoft.Win32.Registry]::CurrentUser
    $rootKey = $base.OpenSubKey($SubKey, $false)
    if ($null -eq $rootKey) {
        $empty = [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-registry-tree-state/v1'
            subkey_sha256 = Get-LabStringSha256 -Value $SubKey
            exists = $false
            entries = @()
        }
        $empty | Add-Member -NotePropertyName state_sha256 `
            -NotePropertyValue (Get-LabStringSha256 -Value (
                $empty | ConvertTo-Json -Depth 32 -Compress))
        return $empty
    }
    $rootKey.Dispose()
    $entries = [System.Collections.Generic.List[object]]::new()
    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push('')
    while ($pending.Count -gt 0) {
        $relative = $pending.Pop()
        $path = if ($relative) { "$SubKey\$relative" } else { $SubKey }
        $key = $base.OpenSubKey($path, $false)
        if ($null -eq $key) {
            throw 'I03_REGISTRY_SNAPSHOT::TREE_CHANGED_DURING_READ'
        }
        try {
            $values = @($key.GetValueNames() | Sort-Object | ForEach-Object {
                $name = [string]$_
                $kind = $key.GetValueKind($name).ToString()
                [pscustomobject][ordered]@{
                    name = $name
                    kind = $kind
                    data = ConvertTo-I03RegistryDataProjection `
                        -Value ($key.GetValue($name, $null,
                            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)) `
                        -Kind $kind
                }
            })
            $entries.Add([pscustomobject][ordered]@{
                relative_path = $relative
                values = $values
            })
            foreach ($child in @($key.GetSubKeyNames() | Sort-Object -Descending)) {
                $childRelative = if ($relative) {
                    "$relative\$child"
                } else { [string]$child }
                $pending.Push($childRelative)
            }
        } finally { $key.Dispose() }
    }
    $state = [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-registry-tree-state/v1'
        subkey_sha256 = Get-LabStringSha256 -Value $SubKey
        exists = $true
        entries = @($entries | Sort-Object relative_path)
    }
    $state | Add-Member -NotePropertyName state_sha256 `
        -NotePropertyValue (Get-LabStringSha256 -Value (
            $state | ConvertTo-Json -Depth 32 -Compress))
    return $state
}

function Get-I03ObjectSha256 {
    param([AllowNull()][object]$Value)
    return Get-LabStringSha256 -Value (
        $Value | ConvertTo-Json -Depth 32 -Compress)
}

function Get-I03RegistryTreeWithoutValueProjection {
    param(
        [Parameter(Mandatory = $true)][object]$State,
        [Parameter(Mandatory = $true)][string]$ValueName
    )

    if ([string]$State.schema -cne
        'ese.v91.i03-registry-tree-state/v1') {
        throw 'I03_REGISTRY_PLAN::TREE_STATE_INVALID'
    }
    return [pscustomobject][ordered]@{
        exists = [bool]$State.exists
        entries = @($State.entries | ForEach-Object {
            [pscustomobject][ordered]@{
                relative_path = [string]$_.relative_path
                values = @($_.values | Where-Object {
                    [string]$_.name -ine $ValueName
                })
            }
        })
    }
}

function Get-I03RegistryCleanupPlan {
    param(
        [Parameter(Mandatory = $true)][object]$Baseline,
        [Parameter(Mandatory = $true)][object]$CurrentAutostart,
        [Parameter(Mandatory = $true)][object]$CurrentRunKey,
        [Parameter(Mandatory = $true)][object]$CurrentEd2kAssociation
    )

    $valueName = 'eMuleAutoStart'
    $result = [ordered]@{
        schema = 'ese.v91.i03-registry-cleanup-plan/v1'
        decision = 'BLOCK_CONCURRENT'
        action = 'NONE'
        remove_empty_run_key = $false
        baseline_sha256 = Get-I03ObjectSha256 -Value $Baseline
        current_sha256 = Get-I03ObjectSha256 -Value ([ordered]@{
            autostart = $CurrentAutostart
            run_key = $CurrentRunKey
            ed2k_association = $CurrentEd2kAssociation
        })
    }
    if ([string]$Baseline.schema -cne
            'ese.v91.i03-mutation-baseline/v2' -or
        [bool]$Baseline.autostart.value_exists -or
        -not [bool]$Baseline.run_key.exists -or
        [bool]$Baseline.ed2k_association.exists -or
        $Baseline.allowed_autostart_value_sha256 -isnot [System.Array] -or
        [string]$CurrentAutostart.schema -cne
            'ese.v91.i03-registry-value-state/v1' -or
        [string]$CurrentRunKey.schema -cne
            'ese.v91.i03-registry-tree-state/v1' -or
        [string]$CurrentEd2kAssociation.schema -cne
            'ese.v91.i03-registry-tree-state/v1') {
        $result.decision = 'BLOCK_BASELINE'
        return [pscustomobject]$result
    }
    if ([bool]$CurrentEd2kAssociation.exists -or
        [string]$CurrentEd2kAssociation.state_sha256 -cne
            [string]$Baseline.ed2k_association.state_sha256) {
        return [pscustomobject]$result
    }

    $targetValues = @($CurrentRunKey.entries | Where-Object {
        [string]$_.relative_path -ceq ''
    } | ForEach-Object { $_.values } | Where-Object {
        [string]$_.name -ieq $valueName
    })
    if ([bool]$CurrentAutostart.value_exists -ne
        ($targetValues.Count -eq 1)) {
        return [pscustomobject]$result
    }
    if ([bool]$CurrentAutostart.value_exists) {
        $allowedValueHashes = @(
            $Baseline.allowed_autostart_value_sha256
        )
        if ($CurrentAutostart.kind -isnot [string] -or
            [string]$CurrentAutostart.kind -cne 'String' -or
            $CurrentAutostart.data -isnot [string] -or
            [string]$targetValues[0].kind -cne
                [string]$CurrentAutostart.kind -or
            [string]$targetValues[0].data -cne
                [string]$CurrentAutostart.data -or
            (Get-LabStringSha256 -Value (
                [string]$CurrentAutostart.data
            )) -cnotin $allowedValueHashes) {
            return [pscustomobject]$result
        }
    }
    $baselineSansTarget = Get-I03RegistryTreeWithoutValueProjection `
        -State $Baseline.run_key -ValueName $valueName
    $currentSansTarget = Get-I03RegistryTreeWithoutValueProjection `
        -State $CurrentRunKey -ValueName $valueName
    if ((Get-I03ObjectSha256 -Value $baselineSansTarget) -cne
        (Get-I03ObjectSha256 -Value $currentSansTarget)) {
        return [pscustomobject]$result
    }

    if ([bool]$CurrentAutostart.value_exists) {
        $result.decision = 'RESTORE_OWNED_VALUE'
        $result.action = 'DELETE_AUTOSTART_VALUE'
    } elseif ([string]$CurrentRunKey.state_sha256 -ceq
        [string]$Baseline.run_key.state_sha256) {
        $result.decision = 'NOOP'
    } else {
        return [pscustomobject]$result
    }
    return [pscustomobject]$result
}

function Get-I03FirewallProjection {
    param(
        [Parameter(Mandatory = $true)][object[]]$Rows,
        [Parameter(Mandatory = $true)][string[]]$Properties
    )

    return @($Rows | Sort-Object InstanceID, Name | ForEach-Object {
        $row = $_
        $projected = [ordered]@{}
        foreach ($name in $Properties) {
            $value = $row.$name
            if ($null -eq $value) {
                $projected[$name] = $null
            } elseif ($value -is [string] -or
                $value.GetType().IsValueType) {
                $projected[$name] = [string]$value
            } else {
                $projected[$name] = @($value | ForEach-Object {
                    [string]$_
                } | Sort-Object)
            }
        }
        [pscustomobject]$projected
    })
}

function Get-I03SystemStateSnapshot {
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop |
        Sort-Object InterfaceGuid | ForEach-Object {
            [pscustomobject][ordered]@{
                interface_guid = [string]$_.InterfaceGuid
                interface_index = [int]$_.InterfaceIndex
                status = [string]$_.Status
                hardware = [bool]$_.HardwareInterface
                virtual = [bool]$_.Virtual
                mac = [string]$_.MacAddress
            }
        })
    $adapterBindings = @(Get-NetAdapterBinding -AllBindings `
        -ErrorAction Stop | Sort-Object InterfaceIndex, ComponentID |
        ForEach-Object {
            [pscustomobject][ordered]@{
                interface_index = [int]$_.InterfaceIndex
                component_id = [string]$_.ComponentID
                display_name = [string]$_.DisplayName
                enabled = [bool]$_.Enabled
            }
        })
    $ipAddresses = @(Get-NetIPAddress -ErrorAction Stop |
        Sort-Object AddressFamily, InterfaceIndex, IPAddress |
        ForEach-Object {
            [pscustomobject][ordered]@{
                family = [string]$_.AddressFamily
                interface_index = [int]$_.InterfaceIndex
                address = Get-I03NormalizedIp -Address ([string]$_.IPAddress)
                prefix_length = [int]$_.PrefixLength
                type = [string]$_.Type
                address_state = [string]$_.AddressState
                prefix_origin = [string]$_.PrefixOrigin
                suffix_origin = [string]$_.SuffixOrigin
                skip_as_source = [bool]$_.SkipAsSource
                policy_store = [string]$_.PolicyStore
            }
        })
    $ipInterfaces = @(Get-NetIPInterface -ErrorAction Stop |
        Sort-Object AddressFamily, InterfaceIndex | ForEach-Object {
            [pscustomobject][ordered]@{
                family = [string]$_.AddressFamily
                interface_index = [int]$_.InterfaceIndex
                connection_state = [string]$_.ConnectionState
                dhcp = [string]$_.Dhcp
                forwarding = [string]$_.Forwarding
                advertising = [string]$_.Advertising
                weak_host_send = [string]$_.WeakHostSend
                weak_host_receive = [string]$_.WeakHostReceive
                automatic_metric = [string]$_.AutomaticMetric
                interface_metric = [int]$_.InterfaceMetric
                nl_mtu_bytes = [int]$_.NlMtuBytes
            }
        })
    $routes = @(Get-NetRoute -ErrorAction Stop |
        Sort-Object AddressFamily, DestinationPrefix, InterfaceIndex, NextHop |
        ForEach-Object {
            [pscustomobject][ordered]@{
                family = [string]$_.AddressFamily
                destination = [string]$_.DestinationPrefix
                next_hop = [string]$_.NextHop
                interface_index = [int]$_.InterfaceIndex
                route_metric = [int]$_.RouteMetric
                interface_metric = [int]$_.InterfaceMetric
                state = [string]$_.State
            }
        })
    $dns = @(Get-DnsClientServerAddress -ErrorAction Stop |
        Sort-Object InterfaceIndex, AddressFamily | ForEach-Object {
            [pscustomobject][ordered]@{
                interface_index = [int]$_.InterfaceIndex
                family = [string]$_.AddressFamily
                servers = @([string[]]$_.ServerAddresses)
            }
        })
    $firewallRules = Get-I03FirewallProjection -Rows @(
        Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop
    ) -Properties @(
        'InstanceID', 'Name', 'ID', 'DisplayName', 'Group', 'DisplayGroup',
        'Enabled', 'Profile', 'Profiles', 'Platform', 'Platforms',
        'Direction', 'Action', 'EdgeTraversalPolicy', 'LocalOnlyMapping',
        'LooseSourceMapping', 'Owner', 'PackageFamilyName', 'PolicyAppId',
        'PrimaryStatus', 'Status', 'StatusCode', 'EnforcementStatus',
        'PolicyStoreSource', 'PolicyStoreSourceType'
    )
    $firewallPorts = Get-I03FirewallProjection -Rows @(
        Get-NetFirewallPortFilter -PolicyStore ActiveStore -ErrorAction Stop
    ) -Properties @(
        'InstanceID', 'Protocol', 'LocalPort', 'RemotePort', 'IcmpType',
        'DynamicTarget', 'DynamicTransport'
    )
    $firewallApps = Get-I03FirewallProjection -Rows @(
        Get-NetFirewallApplicationFilter -PolicyStore ActiveStore `
            -ErrorAction Stop
    ) -Properties @('InstanceID', 'Program', 'AppPath', 'Package')
    $firewallAddresses = Get-I03FirewallProjection -Rows @(
        Get-NetFirewallAddressFilter -PolicyStore ActiveStore `
            -ErrorAction Stop
    ) -Properties @(
        'InstanceID', 'LocalAddress', 'LocalIP', 'RemoteAddress', 'RemoteIP'
    )
    $firewallInterfaces = Get-I03FirewallProjection -Rows @(
        Get-NetFirewallInterfaceFilter -PolicyStore ActiveStore `
            -ErrorAction Stop
    ) -Properties @('InstanceID', 'InterfaceAlias')
    $firewallInterfaceTypes = Get-I03FirewallProjection -Rows @(
        Get-NetFirewallInterfaceTypeFilter -PolicyStore ActiveStore `
            -ErrorAction Stop
    ) -Properties @('InstanceID', 'InterfaceType')
    $firewallServices = Get-I03FirewallProjection -Rows @(
        Get-NetFirewallServiceFilter -PolicyStore ActiveStore `
            -ErrorAction Stop
    ) -Properties @('InstanceID', 'Service', 'ServiceName')
    $firewallSecurity = Get-I03FirewallProjection -Rows @(
        Get-NetFirewallSecurityFilter -PolicyStore ActiveStore `
            -ErrorAction Stop
    ) -Properties @(
        'InstanceID', 'Authentication', 'Encryption', 'LocalUser',
        'LocalUsers', 'RemoteUser', 'RemoteUsers', 'RemoteMachine',
        'RemoteMachines', 'OverrideBlockRules'
    )
    $firewallProfiles = Get-I03FirewallProjection -Rows @(
        Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop
    ) -Properties @(
        'InstanceID', 'Name', 'Profile', 'Enabled',
        'DefaultInboundAction', 'DefaultOutboundAction',
        'AllowInboundRules', 'AllowLocalFirewallRules',
        'AllowLocalIPsecRules', 'AllowUserApps', 'AllowUserPorts',
        'AllowUnicastResponseToMulticast', 'NotifyOnListen',
        'EnableStealthModeForIPsec', 'DisabledInterfaceAliases',
        'LogFileName', 'LogMaxSizeKilobytes', 'LogAllowed',
        'LogBlocked', 'LogIgnored'
    )
    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $hostsHash = if (Test-Path -LiteralPath $hostsPath -PathType Leaf) {
        Get-LabSha256 -Path $hostsPath
    } else { Get-LabStringSha256 -Value '<missing>' }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-forbidden-state-digests/v1'
        adapters_sha256 = Get-I03ObjectSha256 -Value $adapters
        adapter_bindings_sha256 =
            Get-I03ObjectSha256 -Value $adapterBindings
        ip_addresses_sha256 = Get-I03ObjectSha256 -Value $ipAddresses
        ip_interfaces_sha256 = Get-I03ObjectSha256 -Value $ipInterfaces
        routes_sha256 = Get-I03ObjectSha256 -Value $routes
        dns_sha256 = Get-I03ObjectSha256 -Value $dns
        firewall_rules_sha256 = Get-I03ObjectSha256 -Value $firewallRules
        firewall_ports_sha256 = Get-I03ObjectSha256 -Value $firewallPorts
        firewall_apps_sha256 = Get-I03ObjectSha256 -Value $firewallApps
        firewall_addresses_sha256 =
            Get-I03ObjectSha256 -Value $firewallAddresses
        firewall_interfaces_sha256 =
            Get-I03ObjectSha256 -Value $firewallInterfaces
        firewall_interface_types_sha256 =
            Get-I03ObjectSha256 -Value $firewallInterfaceTypes
        firewall_services_sha256 =
            Get-I03ObjectSha256 -Value $firewallServices
        firewall_security_sha256 =
            Get-I03ObjectSha256 -Value $firewallSecurity
        firewall_profiles_sha256 =
            Get-I03ObjectSha256 -Value $firewallProfiles
        hosts_sha256 = $hostsHash
    }
}

function Test-I03SystemStateSnapshot {
    param(
        [AllowNull()][object]$Before,
        [AllowNull()][object]$After
    )

    if ($null -eq $Before -or $null -eq $After -or
        [string]$Before.schema -cne
            'ese.v91.i03-forbidden-state-digests/v1' -or
        [string]$After.schema -cne
            'ese.v91.i03-forbidden-state-digests/v1') { return $false }
    foreach ($name in @(
        'adapters_sha256', 'adapter_bindings_sha256',
        'ip_addresses_sha256', 'ip_interfaces_sha256',
        'routes_sha256', 'dns_sha256',
        'firewall_rules_sha256', 'firewall_ports_sha256',
        'firewall_apps_sha256', 'firewall_addresses_sha256',
        'firewall_interfaces_sha256',
        'firewall_interface_types_sha256',
        'firewall_services_sha256', 'firewall_security_sha256',
        'firewall_profiles_sha256', 'hosts_sha256'
    )) {
        if ([string]$Before.$name -cne [string]$After.$name) {
            return $false
        }
    }
    return $true
}

function Get-I03MutationBaseline {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()][string[]]$AllowedAutostartValueSha256
    )

    $runSubKey = 'Software\Microsoft\Windows\CurrentVersion\Run'
    $runValue = 'eMuleAutoStart'
    $ed2kSubKey = 'Software\Classes\ed2k'
    $autostart = Get-I03RegistryValueState -SubKey $runSubKey `
        -ValueName $runValue
    $runKey = Get-I03RegistryTreeState -SubKey $runSubKey
    $ed2k = Get-I03RegistryTreeState -SubKey $ed2kSubKey
    if (-not [bool]$runKey.exists -or
        [bool]$autostart.value_exists -or [bool]$ed2k.exists) {
        throw 'I03_ACCOUNT_GATE::NONEMPTY_AUTOSTART_OR_ED2K'
    }
    if ($currentLabSidHash -cne $expectedLabSidHash -or
        -not $DisposableLabAccountAcknowledged) {
        throw 'I03_ACCOUNT_GATE::SID_NOT_BOUND'
    }
    foreach ($hash in $AllowedAutostartValueSha256) {
        if ([string]$hash -notmatch '^[0-9a-f]{64}$') {
            throw 'I03_ACCOUNT_GATE::AUTOSTART_BINDING_INVALID'
        }
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-mutation-baseline/v2'
        lab_user_sid_sha256 = $currentLabSidHash
        allowed_autostart_value_sha256 =
            [object[]]@($AllowedAutostartValueSha256)
        forbidden_state = Get-I03SystemStateSnapshot
        autostart = $autostart
        run_key = $runKey
        ed2k_association = $ed2k
    }
}

function Complete-I03MutationTransaction {
    param([Parameter(Mandatory = $true)][object]$Baseline)

    if ([string]$Baseline.schema -cne
            'ese.v91.i03-mutation-baseline/v2' -or
        [string]$Baseline.lab_user_sid_sha256 -cne
            $currentLabSidHash -or
        $currentLabSidHash -cne $expectedLabSidHash) {
        throw 'I03_CLEANUP::MUTATION_BASELINE_INVALID'
    }
    $runSubKey = 'Software\Microsoft\Windows\CurrentVersion\Run'
    $runValue = 'eMuleAutoStart'
    $ed2kSubKey = 'Software\Classes\ed2k'
    $currentAutostart = Get-I03RegistryValueState -SubKey $runSubKey `
        -ValueName $runValue
    $currentRunKey = Get-I03RegistryTreeState -SubKey $runSubKey
    $currentEd2k = Get-I03RegistryTreeState -SubKey $ed2kSubKey
    $plan = Get-I03RegistryCleanupPlan -Baseline $Baseline `
        -CurrentAutostart $currentAutostart `
        -CurrentRunKey $currentRunKey `
        -CurrentEd2kAssociation $currentEd2k
    $registryMutationPerformed = $false
    if ([string]$plan.action -ceq 'DELETE_AUTOSTART_VALUE') {
        $freshAutostart = Get-I03RegistryValueState -SubKey $runSubKey `
            -ValueName $runValue
        $freshRunKey = Get-I03RegistryTreeState -SubKey $runSubKey
        $freshEd2k = Get-I03RegistryTreeState -SubKey $ed2kSubKey
        $freshPlan = Get-I03RegistryCleanupPlan -Baseline $Baseline `
            -CurrentAutostart $freshAutostart `
            -CurrentRunKey $freshRunKey `
            -CurrentEd2kAssociation $freshEd2k
        if ([string]$freshPlan.decision -cne
                'RESTORE_OWNED_VALUE' -or
            [string]$freshPlan.current_sha256 -cne
                [string]$plan.current_sha256) {
            throw 'I03_CLEANUP::REGISTRY_CHANGED_DURING_PLAN'
        }
        $base = [Microsoft.Win32.Registry]::CurrentUser
        $key = $base.OpenSubKey($runSubKey, $true)
        if ($null -eq $key) {
            throw 'I03_CLEANUP::RUN_KEY_DISAPPEARED'
        }
        try {
            if (@($key.GetValueNames() | Where-Object {
                        [string]$_ -ieq $runValue
                    }).Count -ne 1) {
                throw 'I03_CLEANUP::AUTOSTART_VALUE_CHANGED'
            }
            $liveKind = $key.GetValueKind($runValue).ToString()
            $liveData = $key.GetValue(
                $runValue, $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            )
            if ($liveKind -cne 'String' -or
                $liveData -isnot [string] -or
                (Get-LabStringSha256 -Value ([string]$liveData)) -cnotin
                    @($Baseline.allowed_autostart_value_sha256)) {
                throw 'I03_CLEANUP::AUTOSTART_VALUE_NOT_OWNED'
            }
            $key.DeleteValue($runValue, $false)
            $registryMutationPerformed = $true
        } finally { $key.Dispose() }
    }
    $afterAutostart = Get-I03RegistryValueState -SubKey $runSubKey `
        -ValueName $runValue
    $afterRunKey = Get-I03RegistryTreeState -SubKey $runSubKey
    $afterEd2k = Get-I03RegistryTreeState -SubKey $ed2kSubKey
    $runRestored = [string]$afterAutostart.state_sha256 -ceq
            [string]$Baseline.autostart.state_sha256 -and
        [string]$afterRunKey.state_sha256 -ceq
            [string]$Baseline.run_key.state_sha256
    $ed2kRestored = -not [bool]$afterEd2k.exists -and
        [string]$afterEd2k.state_sha256 -ceq
            [string]$Baseline.ed2k_association.state_sha256
    $after = Get-I03SystemStateSnapshot
    $forbiddenUnchanged = Test-I03SystemStateSnapshot `
        -Before $Baseline.forbidden_state -After $after
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-mutation-cleanup/v1'
        registry_plan_decision = [string]$plan.decision
        registry_plan_action = [string]$plan.action
        registry_mutation_performed = $registryMutationPerformed
        autostart_restored_exact = $runRestored
        ed2k_association_restored_exact = $ed2kRestored
        forbidden_state_unchanged = $forbiddenUnchanged
        before_digests = $Baseline.forbidden_state
        after_digests = $after
        complete = $runRestored -and $ed2kRestored -and
            $forbiddenUnchanged
    }
}

function Convert-I03ProcessCreationTimeUtc {
    param([Parameter(Mandatory = $true)][object]$Value)

    $parsed = [DateTime]::MinValue
    if ($Value -is [DateTime]) {
        $parsed = [DateTime]$Value
    } elseif ($Value -is [string] -and
        [DateTime]::TryParse(
            [string]$Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$parsed
        )) {
    } elseif ($Value -is [string]) {
        $parsed = [Management.ManagementDateTimeConverter]::ToDateTime(
            [string]$Value
        )
    } else {
        throw 'I03_COLLECTOR::PROCESS_CREATION_TIME_INVALID'
    }
    return $parsed.ToUniversalTime().ToString('o')
}

function Get-I03ProcessLineageDecision {
    param(
        [Parameter(Mandatory = $true)][int]$ExpectedProcessId,
        [Parameter(Mandatory = $true)][int]$ExpectedParentProcessId,
        [Parameter(Mandatory = $true)][string]$ParentStartTimeUtc,
        [Parameter(Mandatory = $true)][int]$CimProcessId,
        [Parameter(Mandatory = $true)][int]$CimParentProcessId,
        [Parameter(Mandatory = $true)][string]$CimCreationTimeUtc,
        [Parameter(Mandatory = $true)][object]$Identity
    )

    $result = [ordered]@{
        schema = 'ese.v91.i03-process-lineage-decision/v1'
        collector_ok = $false
        safe_to_control = $false
        historical_pid_row = $false
        error_code = 'LINEAGE_INVALID'
    }
    $parentStart = [DateTime]::MinValue
    $cimStart = [DateTime]::MinValue
    $identityStart = [DateTime]::MinValue
    if ($null -eq $Identity -or
        @($Identity.PSObject.Properties.Name) -cnotcontains
            'start_time_utc' -or
        -not [DateTime]::TryParseExact(
            $ParentStartTimeUtc, 'o',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$parentStart
        ) -or
        -not [DateTime]::TryParseExact(
            $CimCreationTimeUtc, 'o',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$cimStart
        ) -or
        -not [DateTime]::TryParseExact(
            [string]$Identity.start_time_utc, 'o',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$identityStart
        ) -or $parentStart.Kind -ne [DateTimeKind]::Utc -or
        $cimStart.Kind -ne [DateTimeKind]::Utc -or
        $identityStart.Kind -ne [DateTimeKind]::Utc -or
        -not (Test-I03ProcessIdentityMatch -Expected $Identity `
            -Actual $Identity)) {
        return [pscustomobject]$result
    }
    if ($CimProcessId -ne $ExpectedProcessId -or
        $CimParentProcessId -ne $ExpectedParentProcessId -or
        [int]$Identity.process_id -ne $ExpectedProcessId -or
        $identityStart -ne $cimStart) {
        $result.error_code = 'IDENTITY_CIM_MISMATCH'
        return [pscustomobject]$result
    }
    $result.collector_ok = $true
    if ($cimStart -lt $parentStart) {
        $result.historical_pid_row = $true
        $result.error_code = 'HISTORICAL_PID_ROW'
        return [pscustomobject]$result
    }
    $result.safe_to_control = $true
    $result.error_code = 'NONE'
    return [pscustomobject]$result
}

function Get-I03DescendantProcessSnapshot {
    param(
        [Parameter(Mandatory = $true)][int]$RootProcessId,
        [Parameter(Mandatory = $true)][string]$RootStartTimeUtc
    )

    try {
        $rootStart = [DateTime]::MinValue
        if (-not [DateTime]::TryParseExact(
                $RootStartTimeUtc, 'o',
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind,
                [ref]$rootStart
            ) -or $rootStart.Kind -ne [DateTimeKind]::Utc) {
            throw 'Root start time is invalid'
        }
        $all = @(Get-CimInstance -ClassName Win32_Process `
            -ErrorAction Stop)
        $pending = [System.Collections.Generic.Queue[object]]::new()
        $pending.Enqueue([pscustomobject]@{
            process_id = $RootProcessId
            start_time_utc = $rootStart
        })
        $seen = [System.Collections.Generic.HashSet[int]]::new()
        [void]$seen.Add($RootProcessId)
        $descendants = [System.Collections.Generic.List[object]]::new()
        $historical = [System.Collections.Generic.List[object]]::new()
        while ($pending.Count -gt 0) {
            $parent = $pending.Dequeue()
            foreach ($row in @($all | Where-Object {
                        [int]$_.ParentProcessId -eq
                            [int]$parent.process_id
                    })) {
                $pidValue = [int]$row.ProcessId
                if ($seen.Contains($pidValue)) { continue }
                $process = Get-Process -Id $pidValue -ErrorAction Stop
                $identity = Get-I03ProcessIdentity -Process $process
                $cimCreationTimeUtc =
                    Convert-I03ProcessCreationTimeUtc `
                        -Value $row.CreationDate
                $lineage = Get-I03ProcessLineageDecision `
                    -ExpectedProcessId $pidValue `
                    -ExpectedParentProcessId ([int]$parent.process_id) `
                    -ParentStartTimeUtc (
                        ([DateTime]$parent.start_time_utc).ToString('o')
                    ) -CimProcessId ([int]$row.ProcessId) `
                    -CimParentProcessId ([int]$row.ParentProcessId) `
                    -CimCreationTimeUtc $cimCreationTimeUtc `
                    -Identity $identity
                if (-not [bool]$lineage.collector_ok) {
                    throw 'Descendant CIM/identity binding failed'
                }
                if ([bool]$lineage.historical_pid_row) {
                    $historical.Add([pscustomobject][ordered]@{
                        process_id = $pidValue
                        parent_process_id = [int]$parent.process_id
                        start_time_utc = $cimCreationTimeUtc
                    })
                    continue
                }
                if (-not [bool]$lineage.safe_to_control) {
                    throw 'Descendant lineage was unsafe'
                }
                $childStart = [DateTime]::MinValue
                if (-not [DateTime]::TryParseExact(
                        $cimCreationTimeUtc, 'o',
                        [Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]::RoundtripKind,
                        [ref]$childStart
                    ) -or $childStart.Kind -ne [DateTimeKind]::Utc) {
                    throw 'Descendant start time is invalid'
                }
                [void]$seen.Add($pidValue)
                $descendants.Add([pscustomobject][ordered]@{
                    identity = $identity
                    process = $process
                    cim_binding = [pscustomobject][ordered]@{
                        process_id = $pidValue
                        parent_process_id = [int]$parent.process_id
                        parent_start_time_utc =
                            ([DateTime]$parent.start_time_utc).ToString('o')
                        creation_time_utc = $cimCreationTimeUtc
                    }
                })
                $pending.Enqueue([pscustomobject]@{
                    process_id = $pidValue
                    start_time_utc = $childStart
                })
            }
        }
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-descendant-collector/v1'
            ok = $true
            error_code = 'NONE'
            rows = @($descendants)
            historical_pid_row_count = $historical.Count
            historical_pid_rows = @($historical)
        }
    } catch {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-descendant-collector/v1'
            ok = $false
            error_code = 'DESCENDANT_QUERY_FAILED'
            rows = @()
            historical_pid_row_count = 0
            historical_pid_rows = @()
        }
    }
}

function Stop-I03OwnedProcess {
    param(
        [AllowNull()][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][AllowNull()][object]$ExpectedIdentity,
        [switch]$RequireGraceful
    )

    if ($null -eq $Process) {
        return [pscustomobject][ordered]@{
            stopped = $true
            path_owned = $false
            identity_matched = $false
            graceful = $false
            already_exited = $true
            process_id = $null
            collector_ok = $true
            error_code = 'NO_OWNED_PROCESS'
            unexpected_descendant_count = 0
            descendants_stopped = $true
        }
    }
    $expectedPathHash = Get-LabStringSha256 -Value (
        [IO.Path]::GetFullPath($ExpectedPath))
    $expectedIdentityOwned = $null -ne $ExpectedIdentity -and
        (Test-I03ProcessIdentityMatch -Expected $ExpectedIdentity `
            -Actual $ExpectedIdentity) -and
        [int]$ExpectedIdentity.process_id -eq [int]$Process.Id -and
        [string]$ExpectedIdentity.executable_path_sha256 -ceq
            $expectedPathHash
    if (-not $expectedIdentityOwned) {
        return [pscustomobject][ordered]@{
            stopped = $false
            path_owned = $false
            identity_matched = $false
            graceful = $false
            already_exited = $false
            process_id = $Process.Id
            collector_ok = $false
            error_code = 'EXPECTED_PROCESS_IDENTITY_MISSING_OR_INVALID'
            unexpected_descendant_count = 0
            descendants_stopped = $false
        }
    }

    function Get-I03OwnedRootProcessState {
        param([Parameter(Mandatory = $true)][int]$ProcessId)
        try {
            return [pscustomobject][ordered]@{
                collector_ok = $true
                present = $true
                process = Get-Process -Id $ProcessId -ErrorAction Stop
            }
        } catch {
            try {
                $cimRows = @(Get-CimInstance -ClassName Win32_Process `
                    -Filter "ProcessId = $ProcessId" -ErrorAction Stop)
            } catch {
                return [pscustomobject][ordered]@{
                    collector_ok = $false
                    present = $false
                    process = $null
                }
            }
            return [pscustomobject][ordered]@{
                collector_ok = $cimRows.Count -eq 0
                present = $cimRows.Count -gt 0
                process = $null
            }
        }
    }

    $rootState = Get-I03OwnedRootProcessState -ProcessId $Process.Id
    if (-not [bool]$rootState.collector_ok) {
        return [pscustomobject][ordered]@{
            stopped = $false; path_owned = $true
            identity_matched = $false; graceful = $false
            already_exited = $false; process_id = $Process.Id
            collector_ok = $false; error_code = 'PROCESS_QUERY_FAILED'
            unexpected_descendant_count = 0
            descendants_stopped = $false
        }
    }
    $actual = $rootState.process
    $alreadyExited = -not [bool]$rootState.present
    $identityMatched = $alreadyExited
    if (-not $alreadyExited) {
        try {
            $actualIdentity = Get-I03ProcessIdentity -Process $actual
            $identityMatched = Test-I03ProcessIdentityMatch `
                -Expected $ExpectedIdentity -Actual $actualIdentity
        } catch {
            $rootState = Get-I03OwnedRootProcessState `
                -ProcessId $Process.Id
            if (-not [bool]$rootState.collector_ok) {
                return [pscustomobject][ordered]@{
                    stopped = $false; path_owned = $true
                    identity_matched = $false; graceful = $false
                    already_exited = $false; process_id = $Process.Id
                    collector_ok = $false
                    error_code = 'PROCESS_IDENTITY_QUERY_FAILED'
                    unexpected_descendant_count = 0
                    descendants_stopped = $false
                }
            }
            $alreadyExited = -not [bool]$rootState.present
            $actual = $rootState.process
            $identityMatched = $alreadyExited
        }
        if (-not $identityMatched) {
            return [pscustomobject][ordered]@{
                stopped = $false; path_owned = $false
                identity_matched = $false; graceful = $false
                already_exited = $false; process_id = $Process.Id
                collector_ok = $true
                error_code = 'PROCESS_IDENTITY_MISMATCH'
                unexpected_descendant_count = 0
                descendants_stopped = $false
            }
        }
    }

    $descendantSnapshot = Get-I03DescendantProcessSnapshot `
        -RootProcessId $Process.Id `
        -RootStartTimeUtc ([string]$ExpectedIdentity.start_time_utc)
    if (-not [bool]$descendantSnapshot.ok) {
        return [pscustomobject][ordered]@{
            stopped = $false; path_owned = $true
            identity_matched = $true; graceful = $false
            already_exited = $alreadyExited; process_id = $Process.Id
            collector_ok = $false
            error_code = [string]$descendantSnapshot.error_code
            unexpected_descendant_count = 0
            descendants_stopped = $false
        }
    }
    $verifiedDescendantProcesses =
        [System.Collections.Generic.List[object]]::new()
    if (-not $alreadyExited) {
        $preStopRootState = Get-I03OwnedRootProcessState `
            -ProcessId $Process.Id
        if (-not [bool]$preStopRootState.collector_ok) {
            return [pscustomobject][ordered]@{
                stopped = $false; path_owned = $true
                identity_matched = $false; graceful = $false
                already_exited = $false; process_id = $Process.Id
                collector_ok = $false
                error_code = 'ROOT_REVALIDATION_QUERY_FAILED'
                unexpected_descendant_count =
                    @($descendantSnapshot.rows).Count
                descendants_stopped = $false
            }
        }
        if (-not [bool]$preStopRootState.present) {
            $alreadyExited = $true
            $actual = $null
        } else {
            try {
                [void]$preStopRootState.process.Handle
                $preStopRootIdentity = Get-I03ProcessIdentity `
                    -Process $preStopRootState.process
            } catch {
                return [pscustomobject][ordered]@{
                    stopped = $false; path_owned = $true
                    identity_matched = $false; graceful = $false
                    already_exited = $false; process_id = $Process.Id
                    collector_ok = $false
                    error_code = 'ROOT_REVALIDATION_IDENTITY_FAILED'
                    unexpected_descendant_count =
                        @($descendantSnapshot.rows).Count
                    descendants_stopped = $false
                }
            }
            if (-not (Test-I03ProcessIdentityMatch `
                    -Expected $ExpectedIdentity `
                    -Actual $preStopRootIdentity)) {
                return [pscustomobject][ordered]@{
                    stopped = $false; path_owned = $false
                    identity_matched = $false; graceful = $false
                    already_exited = $false; process_id = $Process.Id
                    collector_ok = $true
                    error_code = 'ROOT_IDENTITY_CHANGED_BEFORE_STOP'
                    unexpected_descendant_count =
                        @($descendantSnapshot.rows).Count
                    descendants_stopped = $false
                }
            }
            $actual = $preStopRootState.process
            # The handle was acquired before identity inspection. Later
            # CloseMainWindow/Kill targets that object, never a reused PID.
        }
    }
    if (-not $alreadyExited) {
        try {
            foreach ($descendant in @($descendantSnapshot.rows)) {
                $binding = $descendant.cim_binding
                $descendantPid = [int]$descendant.identity.process_id
                $currentCim = @(Get-CimInstance `
                    -ClassName Win32_Process `
                    -Filter "ProcessId = $descendantPid" `
                    -ErrorAction Stop)
                if ($currentCim.Count -ne 1) {
                    throw 'Descendant CIM row disappeared or became ambiguous'
                }
                $currentCreation =
                    Convert-I03ProcessCreationTimeUtc `
                        -Value $currentCim[0].CreationDate
                if ([int]$currentCim[0].ParentProcessId -ne
                        [int]$binding.parent_process_id -or
                    $currentCreation -cne
                        [string]$binding.creation_time_utc) {
                    throw 'Descendant CIM binding changed'
                }
                $current = Get-Process -Id $descendantPid `
                    -ErrorAction Stop
                [void]$current.Handle
                $currentIdentity = Get-I03ProcessIdentity -Process $current
                $lineage = Get-I03ProcessLineageDecision `
                    -ExpectedProcessId $descendantPid `
                    -ExpectedParentProcessId `
                        ([int]$binding.parent_process_id) `
                    -ParentStartTimeUtc `
                        ([string]$binding.parent_start_time_utc) `
                    -CimProcessId ([int]$currentCim[0].ProcessId) `
                    -CimParentProcessId `
                        ([int]$currentCim[0].ParentProcessId) `
                    -CimCreationTimeUtc $currentCreation `
                    -Identity $currentIdentity
                if (-not [bool]$lineage.collector_ok -or
                    -not [bool]$lineage.safe_to_control -or
                    -not (Test-I03ProcessIdentityMatch `
                        -Expected $descendant.identity `
                        -Actual $currentIdentity)) {
                    throw 'Descendant identity revalidation failed'
                }
                $verifiedDescendantProcesses.Add($current)
            }
        } catch {
            return [pscustomobject][ordered]@{
                stopped = $false; path_owned = $true
                identity_matched = $true; graceful = $false
                already_exited = $false; process_id = $Process.Id
                collector_ok = $false
                error_code = 'DESCENDANT_REVALIDATION_FAILED'
                unexpected_descendant_count =
                    @($descendantSnapshot.rows).Count
                descendants_stopped = $false
            }
        }
    }

    $graceful = $false
    $stopError = 'NONE'
    if (-not $alreadyExited) {
        try {
            $actual.Refresh()
            if ($actual.MainWindowHandle -ne [IntPtr]::Zero) {
                $null = $actual.CloseMainWindow()
                $graceful = $actual.WaitForExit(15000)
            }
            if (-not $graceful -and -not $RequireGraceful) {
                $actual.Kill()
                $null = $actual.WaitForExit(10000)
            }
        } catch { $stopError = 'PROCESS_STOP_FAILED' }
    }
    $descendantsStopped = $true
    $descendantCollectorOk = $true
    if ($alreadyExited) {
        # Once the root is gone, a PID-reuse window makes newly discovered
        # descendants unsafe to kill. Census them and fail cleanup closed.
        $descendantsStopped = @($descendantSnapshot.rows).Count -eq 0
    } else {
        foreach ($current in @($verifiedDescendantProcesses)) {
            try {
                $current.Kill()
                if (-not $current.WaitForExit(10000)) {
                    $descendantsStopped = $false
                }
            } catch {
                $descendantCollectorOk = $false
                $descendantsStopped = $false
            }
        }
    }
    $finalDescendantSnapshot = Get-I03DescendantProcessSnapshot `
        -RootProcessId $Process.Id `
        -RootStartTimeUtc ([string]$ExpectedIdentity.start_time_utc)
    if (-not [bool]$finalDescendantSnapshot.ok) {
        $descendantCollectorOk = $false
        $descendantsStopped = $false
    } elseif (@($finalDescendantSnapshot.rows).Count -gt 0) {
        $descendantsStopped = $false
    }
    $finalRootState = Get-I03OwnedRootProcessState -ProcessId $Process.Id
    $collectorOk = [bool]$finalRootState.collector_ok -and
        $descendantCollectorOk
    $stopped = $collectorOk -and -not [bool]$finalRootState.present -and
        $descendantsStopped
    return [pscustomobject][ordered]@{
        stopped = $stopped
        path_owned = $true
        identity_matched = $true
        graceful = $graceful
        already_exited = $alreadyExited
        process_id = $Process.Id
        collector_ok = $collectorOk
        error_code = if ($stopped) {
            if ($alreadyExited) { 'PROCESS_ALREADY_EXITED_DESCENDANTS_CENSUSED' }
            elseif ($graceful) { 'NONE' } elseif ($stopError -eq 'NONE') {
                'FORCED_STOP'
            } else { $stopError }
        } elseif (-not $collectorOk) { 'PROCESS_FINAL_CENSUS_FAILED' }
        else { 'PROCESS_OR_DESCENDANT_REMAINS' }
        unexpected_descendant_count = [Math]::Max(
            @($descendantSnapshot.rows).Count,
            @($finalDescendantSnapshot.rows).Count
        )
        descendants_stopped = $descendantsStopped
    }
}

function Get-I03UserHashSha256 {
    param([Parameter(Mandatory = $true)][string]$NodePath)

    $path = Join-Path $NodePath 'config\preferences.dat'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Stable peer identity file is missing: $path"
    }
    $bytes = [IO.File]::ReadAllBytes($path)
    if ($bytes.Length -lt 17) {
        throw "Stable peer identity file is truncated: $path"
    }
    $identity = New-Object byte[] 16
    [Array]::Copy($bytes, 1, $identity, 0, 16)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $sha.ComputeHash($identity)
        )).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-I03Md5Text {
    param([Parameter(Mandatory = $true)][string]$Value)

    $md5 = [Security.Cryptography.MD5]::Create()
    try {
        return ([BitConverter]::ToString(
            $md5.ComputeHash([Text.Encoding]::Unicode.GetBytes($Value))
        )).Replace('-', '')
    } finally {
        $md5.Dispose()
    }
}

function Get-I03ClassicSession {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Password
    )

    $encoded = [Uri]::EscapeDataString($Password)
    $deadline = [DateTime]::UtcNow.AddMinutes(10)
    do {
        try {
            $response = Invoke-WebRequest `
                -Uri "http://127.0.0.1:$Port/?w=password&p=$encoded" `
                -UseBasicParsing -TimeoutSec 10
            $match = [regex]::Match($response.Content, 'ses=(\d+)')
            if ($match.Success) { return $match.Groups[1].Value }
        } catch {}
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Classic WebServer login failed on port $Port"
}

function Get-I03SharedLink {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Session,
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][Int64]$FileBytes
    )

    $deadline = [DateTime]::UtcNow.AddMinutes(10)
    $pattern = 'ed2k://\|file\|' + [regex]::Escape($FileName) +
        '\|' + $FileBytes + '\|([A-Fa-f0-9]{32})' +
        '(?:\|h=[A-Z2-7]{32})?\|/'
    do {
        try {
            $response = Invoke-WebRequest `
                -Uri "http://127.0.0.1:$Port/?ses=$Session&w=shared" `
                -UseBasicParsing -TimeoutSec 15
            $match = [regex]::Match($response.Content, $pattern)
            if ($match.Success) {
                return [pscustomobject][ordered]@{
                    link = $match.Value
                    ed2k_hash = $match.Groups[1].Value.ToUpperInvariant()
                }
            }
        } catch {}
        Start-Sleep -Seconds 1
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Timed out waiting for the unique I03 fixture to enter the shared list'
}

function Send-I03Ed2kLink {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$Link
    )

    if (-not ('V91I03CopyDataTimeout' -as [type])) {
        Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class V91I03CopyDataTimeout {
    [StructLayout(LayoutKind.Sequential)]
    public struct COPYDATASTRUCT {
        public IntPtr dwData;
        public int cbData;
        public IntPtr lpData;
    }
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr hWnd, uint msg, IntPtr wParam,
        ref COPYDATASTRUCT lParam, uint flags, uint timeoutMs,
        out UIntPtr result);
}
'@
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $handle = [IntPtr]::Zero
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw 'Client exited before direct-link injection'
        }
        $handle = $Process.MainWindowHandle
        if ($handle -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($handle -eq [IntPtr]::Zero) {
        throw 'Client main window handle was unavailable'
    }

    $pointer = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($Link)
    try {
        $payload = New-Object V91I03CopyDataTimeout+COPYDATASTRUCT
        $payload.dwData = [IntPtr]12000
        $payload.cbData = ($Link.Length + 1) * 2
        $payload.lpData = $pointer
        $nativeResult = [UIntPtr]::Zero
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $sent = [V91I03CopyDataTimeout]::SendMessageTimeout(
            $handle, 0x004A, [IntPtr]::Zero, [ref]$payload,
            0x0003, 10000, [ref]$nativeResult
        )
        $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $watch.Stop()
        if ($sent -eq [IntPtr]::Zero) {
            throw (
                'WM_COPYDATA delivery timed out or failed after ' +
                "$($watch.ElapsedMilliseconds) ms (Win32=$lastError)"
            )
        }
        if ($nativeResult.ToUInt64() -eq 0) {
            throw 'Candidate rejected the WM_COPYDATA eD2K link'
        }
        return [pscustomobject][ordered]@{
            delivered = $true
            accepted = $true
            duration_ms = [Int64]$watch.ElapsedMilliseconds
            native_result = $nativeResult.ToUInt64()
            timeout_ms = 10000
            flags = 'SMTO_ABORTIFHUNG|SMTO_BLOCK'
        }
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($pointer)
    }
}

function Get-I03ImmutableLogSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$SnapshotRoot,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[a-z0-9-]{1,32}$')][string]$Label,
        [switch]$Persist
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetFullPath($SourceRoot).TrimEnd('\') + '\'
    if (-not $fullPath.StartsWith($root,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'I03_EVIDENCE::LOG_OUTSIDE_SOURCE_ROOT'
    }
    $stream = [IO.FileStream]::new(
        $fullPath, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite
    )
    try {
        $memory = [IO.MemoryStream]::new()
        try {
            $stream.CopyTo($memory)
            $bytes = $memory.ToArray()
        } finally {
            $memory.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
    $shaObject = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = ([BitConverter]::ToString(
            $shaObject.ComputeHash($bytes)
        )).Replace('-', '').ToLowerInvariant()
    } finally {
        $shaObject.Dispose()
    }
    $snapshotName = '{0}-{1}.log.snapshot' -f $Label, $hash
    if ($Persist) {
        $snapshotDirectory = New-LabDirectory -Path $SnapshotRoot
        $snapshotPath = Join-Path $snapshotDirectory $snapshotName
        if (-not (Test-Path -LiteralPath $snapshotPath -PathType Leaf)) {
            try {
                $snapshotStream = [IO.FileStream]::new(
                    $snapshotPath, [IO.FileMode]::CreateNew,
                    [IO.FileAccess]::Write, [IO.FileShare]::None
                )
                try {
                    $snapshotStream.Write($bytes, 0, $bytes.Length)
                    $snapshotStream.Flush($true)
                } finally {
                    $snapshotStream.Dispose()
                }
            } catch [IO.IOException] {
                if (-not (Test-Path -LiteralPath $snapshotPath `
                        -PathType Leaf)) {
                    throw
                }
            }
        }
        if ((Get-LabSha256 -Path $snapshotPath) -cne $hash -or
            [Int64](Get-Item -LiteralPath $snapshotPath `
                -ErrorAction Stop).Length -ne [Int64]$bytes.Length) {
            throw 'I03_EVIDENCE::IMMUTABLE_LOG_SNAPSHOT_MISMATCH'
        }
    }

    $offset = 0
    $encoding = [Text.Encoding]::UTF8
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and
        $bytes[1] -eq 0xFE) {
        $encoding = [Text.Encoding]::Unicode
        $offset = 2
    } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and
        $bytes[1] -eq 0xFF) {
        $encoding = [Text.Encoding]::BigEndianUnicode
        $offset = 2
    } elseif ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and
        $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $offset = 3
    }
    $content = $encoding.GetString($bytes, $offset, $bytes.Length - $offset)
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-immutable-log-snapshot/v1'
        relative_source_path = $fullPath.Substring($root.Length)
        source_bytes = [Int64]$bytes.Length
        source_sha256 = $hash
        snapshot_persisted = [bool]$Persist
        snapshot_file = if ($Persist) { $snapshotName } else { '' }
        snapshot_bytes = [Int64]$bytes.Length
        snapshot_sha256 = $hash
        content = $content
    }
}

function Get-I03HelloEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][string]$ExpectedIPv6,
        [Parameter(Mandatory = $true)][string]$SnapshotRoot,
        [switch]$PersistSnapshots
    )

    $highId = 0
    $lowIdLike = 0
    $files = @()
    try {
        $logs = @(Get-ChildItem -LiteralPath $NodePath -Recurse -File `
            -Filter '*.log' -ErrorAction Stop)
    } catch {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-hello-log-collector/v2'
            collector_ok = $false
            collector_error_code = 'LOG_ENUMERATION_FAILED'
            captured_at_utc = Get-LabUtcTimestamp
            highid_hello_answer_count = 0
            lowid_like_hello_answer_count = 0
            learned_public_ipv6_via_hello = $false
            files = @()
        }
    }
    if ($logs.Count -eq 0) {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-hello-log-collector/v2'
            collector_ok = $false
            collector_error_code = 'EXPECTED_LOG_NOT_FOUND'
            captured_at_utc = Get-LabUtcTimestamp
            highid_hello_answer_count = 0
            lowid_like_hello_answer_count = 0
            learned_public_ipv6_via_hello = $false
            files = @()
        }
    }
    foreach ($log in $logs) {
        try {
            $snapshot = Get-I03ImmutableLogSnapshot `
                -Path $log.FullName -SourceRoot $NodePath `
                -SnapshotRoot $SnapshotRoot -Label 'hello' `
                -Persist:$PersistSnapshots
            $lines = @([regex]::Split(
                [string]$snapshot.content, '\r?\n'
            ))
        } catch {
            return [pscustomobject][ordered]@{
                schema = 'ese.v91.i03-hello-log-collector/v2'
                collector_ok = $false
                collector_error_code = 'LOG_READ_FAILED'
                captured_at_utc = Get-LabUtcTimestamp
                highid_hello_answer_count = 0
                lowid_like_hello_answer_count = 0
                learned_public_ipv6_via_hello = $false
                files = @()
            }
        }
        foreach ($lineObject in $lines) {
            $line = [string]$lineObject
            if ($line -notmatch 'OP_HelloAnswer\s+from\s+([^\s]+)') {
                continue
            }
            $firstToken = $Matches[1].Trim('[', ']', '(', ')')
            $parsed = $null
            if ([Net.IPAddress]::TryParse($firstToken.Split('%')[0],
                [ref]$parsed) -and
                (Get-I03NormalizedIp -Address $parsed.ToString()) -eq
                    $ExpectedIPv6) {
                # HighID DbgGetClientInfo begins with the endpoint. LowID begins
                # with "<id>@<server>" and only mentions IPv6 in parentheses.
                $highId++
            } elseif ($line -match [regex]::Escape($ExpectedIPv6) -and
                $firstToken.Contains('@')) {
                $lowIdLike++
            }
        }
        $files += [pscustomobject][ordered]@{
            relative_path = [string]$snapshot.relative_source_path
            bytes = [Int64]$snapshot.source_bytes
            sha256 = [string]$snapshot.source_sha256
            snapshot_persisted = [bool]$snapshot.snapshot_persisted
            snapshot_file = [string]$snapshot.snapshot_file
            snapshot_bytes = [Int64]$snapshot.snapshot_bytes
            snapshot_sha256 = [string]$snapshot.snapshot_sha256
        }
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-hello-log-collector/v2'
        collector_ok = $true
        collector_error_code = 'NONE'
        captured_at_utc = Get-LabUtcTimestamp
        expected_ipv6_sha256 = Get-LabStringSha256 -Value $ExpectedIPv6
        highid_hello_answer_count = $highId
        lowid_like_hello_answer_count = $lowIdLike
        learned_public_ipv6_via_hello = $highId -gt 0 -and $lowIdLike -eq 0
        files = $files
    }
}

function Get-I03IniExactValueEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Expected
    )

    $sectionCount = 0
    $keyCount = 0
    $match = $false
    $canonicalCasing = $false
    $currentSection = ''
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        if ($line -match '^\s*\[([^\]]+)\]\s*$') {
            $currentSection = [string]$Matches[1]
            if ([StringComparer]::OrdinalIgnoreCase.Equals(
                    $currentSection, $Section)) { $sectionCount++ }
            continue
        }
        if ([StringComparer]::OrdinalIgnoreCase.Equals(
                $currentSection, $Section) -and
            $line -match '^\s*([^;#][^=]*?)\s*=\s*(.*?)\s*$' -and
            [StringComparer]::OrdinalIgnoreCase.Equals(
                [string]$Matches[1], $Key)) {
            $keyCount++
            $match = [string]$Matches[2] -ceq $Expected
            $canonicalCasing = $currentSection -ceq $Section -and
                [string]$Matches[1] -ceq $Key
        }
    }
    return [pscustomobject][ordered]@{
        section = $Section
        key = $Key
        section_count = $sectionCount
        key_count = $keyCount
        expected_value_sha256 = Get-LabStringSha256 -Value $Expected
        exact = $sectionCount -eq 1 -and $keyCount -eq 1 -and
            $match -and $canonicalCasing
    }
}

function Assert-I03PreferenceContract {
    param(
        [Parameter(Mandatory = $true)][string]$PreferencesPath,
        [Parameter(Mandatory = $true)][int]$IPv6Mode,
        [Parameter(Mandatory = $true)][string]$IPv6BindAddress,
        [Parameter(Mandatory = $true)][int]$WebPort,
        [ValidateSet(0, 1)][int]$NetworkEd2k = 0
    )

    $expected = @(
        @('eMule', 'OpenPortsOnStartUp', '0'),
        @('eMule', 'AutoTakeED2KLinks', '0'),
        @('eMule', 'WatchClipboard4ED2kFilelinks', '0'),
        @('eMule', 'AutoStart', '0'),
        @('eMule', 'NetworkKademlia', '0'),
        @('eMule', 'Serverlist', '0'),
        @('eMule', 'AddServersFromServer', '0'),
        @('eMule', 'AddServersFromClient', '0'),
        @('Connection', 'IPv6Mode', [string]$IPv6Mode),
        @('Connection', 'IPv6BindAddr', $IPv6BindAddress),
        @('Connection', 'KadNetworkMask', '0'),
        @('Connection', 'NetworkED2K', [string]$NetworkEd2k),
        @('Connection', 'CryptLayerRequested', '0'),
        @('Connection', 'CryptLayerRequired', '0'),
        @('Connection', 'CryptLayerSupported', '0'),
        @('eSE', 'EseNetLabConsent', '1'),
        @('eSE', 'EseNetLabAdvancedConsent', '1'),
        @('eSE', 'EseNetLabContributionConsent', '1'),
        @('eSE', 'EseNetLabEnabled', '0'),
        @('eSE', 'EseV9Experimental', '0'),
        @('eSE', 'EnableUtpHolePunch', '0'),
        @('eSE', 'EseAutoKeepalive', '0'),
        @('eSE', 'EseKad3Rendezvous', '0'),
        @('eSE', 'EseReachSelector', '0'),
        @('eSE', 'EseHolePunchPortPredict', '0'),
        @('eSE', 'EseEd2kPunch3', '0'),
        @('eSE', 'EseRelayAccept', '0'),
        @('eSE', 'EseRelayEgress', '0'),
        @('eSE', 'Kad6BetaExitOptIn', '0'),
        @('Proxy', 'ProxyEnableProxy', '0'),
        @('UPnP', 'EnableUPnP', '0'),
        @('WebServer', 'Enabled', '1'),
        @('WebServer', 'Port', [string]$WebPort),
        @('WebServer', 'AllowedIPs', '127.0.0.1'),
        @('WebServer', 'WebUseUPnP', '0')
    )
    $checks = @($expected | ForEach-Object {
        Get-I03IniExactValueEvidence -Path $PreferencesPath `
            -Section ([string]$_[0]) -Key ([string]$_[1]) `
            -Expected ([string]$_[2])
    })
    if (@($checks | Where-Object { -not [bool]$_.exact }).Count -gt 0) {
        throw 'I03_CONFIG_CONTRACT::MISSING_DUPLICATE_OR_WRONG_VALUE'
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-effective-config-proof/v1'
        verified = $true
        exact_key_count = $checks.Count
        contract_sha256 = Get-LabStringSha256 -Value (
            ($checks | ConvertTo-Json -Depth 4 -Compress))
    }
}

function Set-I03IsolatedPreferences {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][int]$IPv6Mode,
        [Parameter(Mandatory = $true)][string]$IPv6BindAddress,
        [Parameter(Mandatory = $true)][int]$WebPort,
        [Parameter(Mandatory = $true)][string]$Password,
        [Parameter(Mandatory = $true)][string]$IncomingPath,
        [Parameter(Mandatory = $true)][string]$TempPath,
        [ValidateRange(0, 1024)][int]$MaxUploadKiBps = 0
    )

    $config = Join-Path $NodePath 'config'
    $preferences = Join-Path $config 'preferences.ini'
    $removedIdentityFiles =
        [System.Collections.Generic.List[string]]::new()
    foreach ($identityName in @(
        'preferences.dat', 'cryptkey.dat', 'clients.met'
    )) {
        $identityPath = Join-Path $config $identityName
        if (Test-Path -LiteralPath $identityPath -PathType Leaf) {
            Remove-Item -LiteralPath $identityPath -Force `
                -ErrorAction Stop
            $removedIdentityFiles.Add($identityName)
        }
    }
    foreach ($entry in ([ordered]@{
        Autoconnect = '0'
        OpenPortsOnStartUp = '0'
        AutoTakeED2KLinks = '0'
        WatchClipboard4ED2kFilelinks = '0'
        AutoStart = '0'
        NetworkKademlia = '0'
        Serverlist = '0'
        UpdateNotifyTestClient = '0'
        AddServersFromServer = '0'
        AddServersFromClient = '0'
        VerboseOptions = '1'
        Verbose = '1'
        SaveLogToDisk = '1'
        SaveDebugToDisk = '1'
        DebugClientTCP = '1'
        ConfirmExit = '0'
        IncomingDir = ($IncomingPath + '\')
        TempDir = ($TempPath + '\')
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'eMule' `
            -Key $entry.Key -Value $entry.Value
    }
    if ($MaxUploadKiBps -gt 0) {
        foreach ($entry in ([ordered]@{
            MaxUpload = [string]$MaxUploadKiBps
            UploadCapacityNew = [string]($MaxUploadKiBps * 2)
            MinUpload = '1'
            USSEnabled = '0'
        }).GetEnumerator()) {
            Set-LabIniValue -Path $preferences -Section 'eMule' `
                -Key $entry.Key -Value $entry.Value
        }
    }
    foreach ($entry in ([ordered]@{
        IPv6Mode = [string]$IPv6Mode
        IPv6BindAddr = $IPv6BindAddress
        KadNetworkMask = '0'
        NetworkED2K = '0'
        CryptLayerRequested = '0'
        CryptLayerRequired = '0'
        CryptLayerSupported = '0'
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'Connection' `
            -Key $entry.Key -Value $entry.Value
    }
    foreach ($entry in ([ordered]@{
        EseNetLabConsent = '1'
        EseNetLabAdvancedConsent = '1'
        EseNetLabContributionConsent = '1'
        EseNetLabEnabled = '0'
        EseV9Experimental = '0'
        EnableUtpHolePunch = '0'
        EseAutoKeepalive = '0'
        EseKad3Rendezvous = '0'
        EseReachSelector = '0'
        EseHolePunchPortPredict = '0'
        EseEd2kPunch3 = '0'
        EseRelayAccept = '0'
        EseRelayEgress = '0'
        Kad6BetaExitOptIn = '0'
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'eSE' `
            -Key $entry.Key -Value $entry.Value
    }
    Set-LabIniValue -Path $preferences -Section 'Proxy' `
        -Key 'ProxyEnableProxy' -Value '0'
    Set-LabIniValue -Path $preferences -Section 'UPnP' `
        -Key 'EnableUPnP' -Value '0'
    foreach ($entry in ([ordered]@{
        Enabled = '1'
        Port = [string]$WebPort
        Password = Get-I03Md5Text -Value $Password
        AllowedIPs = '127.0.0.1'
        WebUseUPnP = '0'
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'WebServer' `
            -Key $entry.Key -Value $entry.Value
    }
    Set-LabIniValue -Path $preferences -Section 'KRPRelay' `
        -Key 'KrpRelayEnabled' -Value '0'
    Set-LabIniValue -Path $preferences -Section 'KRPRelay' `
        -Key 'KrpRelayKillSwitch' -Value '1'

    $effectiveContract = Assert-I03PreferenceContract `
        -PreferencesPath $preferences -IPv6Mode $IPv6Mode `
        -IPv6BindAddress $IPv6BindAddress -WebPort $WebPort `
        -NetworkEd2k 0

    # No inherited shared directory may introduce another source. This is an
    # isolated package copy; the candidate package itself is never modified.
    $shares = Join-Path $NodePath 'config\shareddir.dat'
    [IO.File]::WriteAllText($shares, '', (New-Object Text.UTF8Encoding($false)))
    # Route/HELLO evidence must belong to this run, never to a log inherited
    # from the release package copied by prepare_node.ps1.
    try {
        $inheritedRuntimeLogs = @(Get-ChildItem -LiteralPath $NodePath `
            -Recurse -File -Filter '*.log' -ErrorAction Stop)
    } catch {
        throw 'I03_COLLECTOR::INHERITED_LOG_ENUMERATION_FAILED'
    }
    foreach ($runtimeLog in $inheritedRuntimeLogs) {
        Remove-Item -LiteralPath $runtimeLog.FullName -Force `
            -ErrorAction Stop
    }
    return [pscustomobject][ordered]@{
        preferences_ini_path = $preferences
        identity_bootstrap = 'fresh isolated profile'
        inherited_identity_files_removed = @($removedIdentityFiles)
        preferences_dat_absent_before_start =
            -not (Test-Path -LiteralPath (
                Join-Path $config 'preferences.dat'
            ))
        cryptkey_dat_absent_before_start =
            -not (Test-Path -LiteralPath (
                Join-Path $config 'cryptkey.dat'
            ))
        max_upload_kib_per_second = $MaxUploadKiBps
        dynamic_upload_disabled = $MaxUploadKiBps -gt 0
        startup_mutation_controls = [ordered]@{
            open_ports_on_startup = $false
            auto_take_ed2k_links = $false
            watch_clipboard_ed2k_links = $false
            auto_start = $false
        }
        effective_configuration = $effectiveContract
    }
}

function Test-I03PortSetFree {
    param([Parameter(Mandatory = $true)][int[]]$Ports)

    try {
        $tcpRows = @(Get-NetTCPConnection -ErrorAction Stop)
        $udpRows = @(Get-NetUDPEndpoint -ErrorAction Stop)
    } catch {
        throw 'I03_COLLECTOR::PORT_CENSUS_FAILED'
    }
    foreach ($port in $Ports) {
        if (@($tcpRows | Where-Object {
                [int]$_.LocalPort -eq $port
            }).Count -gt 0) {
            throw "I03_PORT_STATE::TCP_PORT_${port}_IN_USE"
        }
        if (@($udpRows | Where-Object {
                [int]$_.LocalPort -eq $port
            }).Count -gt 0) {
            throw "I03_PORT_STATE::UDP_PORT_${port}_IN_USE"
        }
    }
}

function Wait-I03PortSetFree {
    param(
        [Parameter(Mandatory = $true)][int[]]$Ports,
        [ValidateRange(1, 120)][int]$TimeoutSeconds = 30
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            Test-I03PortSetFree -Ports $Ports
            return
        } catch {
            if ([string]$_.Exception.Message -match
                '^I03_COLLECTOR::') {
                throw
            }
            if ([string]$_.Exception.Message -notmatch
                '^I03_PORT_STATE::') {
                throw
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'I03_PORT_STATE::RESERVED_PORT_NOT_FREE'
}

function Get-I03HelloEvidenceDecision {
    param([AllowNull()][object]$Evidence)

    $result = [ordered]@{
        schema = 'ese.v91.i03-hello-evidence-decision/v1'
        status = 'LAB_BLOCKED'
        code = 'COLLECTOR_UNAVAILABLE'
    }
    if ($null -eq $Evidence) {
        return [pscustomobject]$result
    }
    $names = @($Evidence.PSObject.Properties | ForEach-Object {
        [string]$_.Name
    })
    if (@('schema', 'collector_ok', 'collector_error_code' |
            Where-Object { $names -cnotcontains $_ }).Count -gt 0 -or
        [string]$Evidence.schema -cne
        'ese.v91.i03-hello-log-collector/v2' -or
        $Evidence.collector_ok -isnot [bool] -or
        $Evidence.collector_error_code -isnot [string]) {
        return [pscustomobject]$result
    }
    if (-not [bool]$Evidence.collector_ok) {
        if ([string]$Evidence.collector_error_code -ceq
            'EXPECTED_LOG_NOT_FOUND') {
            $result.status = 'PRODUCT_INVARIANT'
            $result.code = 'IPV4_PREWARM_INVARIANT'
        }
        return [pscustomobject]$result
    }
    if ([string]$Evidence.collector_error_code -cne 'NONE') {
        return [pscustomobject]$result
    }
    $result.status = 'PASS'
    $result.code = 'NONE'
    return [pscustomobject]$result
}

function Get-I03PeerDualStackMarker {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][string]$SnapshotRoot,
        [switch]$PersistSnapshots
    )

    $inbound = 0
    $accepted = 0
    $files = @()
    try {
        $logs = @(Get-ChildItem -LiteralPath $NodePath -Recurse -File `
            -Filter '*.log' -ErrorAction Stop)
    } catch {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-peer-dualstack-marker/v1'
            collector_ok = $false
            collector_error_code = 'LOG_ENUMERATION_FAILED'
            captured_at_utc = Get-LabUtcTimestamp
            inbound_reachability_markers = 0
            accepted_native_ipv6_markers = 0
            dualstack_capability_armed = $false
            files = @()
        }
    }
    foreach ($log in $logs) {
        try {
            $snapshot = Get-I03ImmutableLogSnapshot `
                -Path $log.FullName -SourceRoot $NodePath `
                -SnapshotRoot $SnapshotRoot -Label 'peer-dualstack' `
                -Persist:$PersistSnapshots
            $content = [string]$snapshot.content
        } catch {
            return [pscustomobject][ordered]@{
                schema = 'ese.v91.i03-peer-dualstack-marker/v1'
                collector_ok = $false
                collector_error_code = 'LOG_READ_FAILED'
                captured_at_utc = Get-LabUtcTimestamp
                inbound_reachability_markers = 0
                accepted_native_ipv6_markers = 0
                dualstack_capability_armed = $false
                files = @()
            }
        }
        $inbound += @([regex]::Matches(
            $content, '(?i)native IPv6 inbound TCP observed'
        )).Count
        $accepted += @([regex]::Matches(
            $content, '(?i)Accepted native IPv6 client'
        )).Count
        $files += [pscustomobject][ordered]@{
            relative_path = [string]$snapshot.relative_source_path
            bytes = [Int64]$snapshot.source_bytes
            sha256 = [string]$snapshot.source_sha256
            snapshot_persisted = [bool]$snapshot.snapshot_persisted
            snapshot_file = [string]$snapshot.snapshot_file
            snapshot_bytes = [Int64]$snapshot.snapshot_bytes
            snapshot_sha256 = [string]$snapshot.snapshot_sha256
        }
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-peer-dualstack-marker/v1'
        collector_ok = $true
        collector_error_code = 'NONE'
        captured_at_utc = Get-LabUtcTimestamp
        inbound_reachability_markers = $inbound
        accepted_native_ipv6_markers = $accepted
        dualstack_capability_armed = $inbound -gt 0 -and $accepted -gt 0
        files = $files
    }
}

function Wait-I03Prewarm {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][object]$ControlledServer,
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][string]$TempPath,
        [Parameter(Mandatory = $true)][int]$WebPort,
        [Parameter(Mandatory = $true)][int]$TcpPort,
        [Parameter(Mandatory = $true)][int]$UdpPort,
        [Parameter(Mandatory = $true)][string[]]$TargetAddresses,
        [Parameter(Mandatory = $true)][int]$TargetPort,
        [Parameter(Mandatory = $true)][string]$ControlAddress,
        [Parameter(Mandatory = $true)][int]$ControlPort,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$SamplesPath
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastPartWrite = $null
    $progress = $false
    $selected = $null
    $hello = $null
    $apiCount = 0
    $apiFailures = 0
    $apiMaxMs = 0L
    $uiCount = 0
    $uiFailures = 0
    $uiMaxMs = 0L
    $otherPid = [System.Collections.Generic.List[object]]::new()
    $otherPidKeys = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $unexpectedSockets = [System.Collections.Generic.List[object]]::new()
    $unexpectedSocketKeys =
        [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
    $duplicateTargetObservationCount = 0
    $duplicateTargetObservations =
        [System.Collections.Generic.List[object]]::new()
    $nextHealth = [DateTime]::UtcNow
    $lastSignature = ''
    $sample = 0

    do {
        $Process.Refresh()
        if ($Process.HasExited) { throw 'Client exited during IPv4 prewarm' }
        Assert-I03ControlledEd2kServerHealthy -Server $ControlledServer
        $connections = @(Get-I03TargetConnections)
        $processCensus = Get-I03ProcessSocketCensus -ProcessId $Process.Id
        if (-not [bool]$processCensus.collector_ok) {
            throw "I03_COLLECTOR::$($processCensus.collector_error_code)"
        }
        $censusDecision = Get-I03CandidateSocketCensusDecision `
            -Census $processCensus -ProcessId $Process.Id `
            -TcpPort $TcpPort -UdpPort $UdpPort -WebPort $WebPort `
            -TargetAddresses $TargetAddresses -TargetPort $TargetPort `
            -ControlAddress $ControlAddress -ControlPort $ControlPort
        foreach ($unexpectedSocket in @($censusDecision.unexpected_rows)) {
            $socketKey = '{0}|{1}|{2}|{3}|{4}|{5}' -f
                $unexpectedSocket.transport, $unexpectedSocket.state,
                $unexpectedSocket.local_address,
                $unexpectedSocket.local_port,
                $unexpectedSocket.remote_address,
                $unexpectedSocket.remote_port
            if ($unexpectedSocketKeys.Add($socketKey)) {
                $unexpectedSockets.Add($unexpectedSocket)
            }
        }
        foreach ($other in @($connections | Where-Object {
            [int]$_.owning_process -ne $Process.Id -and
            [string]$_.state -in @('SynSent', 'Established')
        })) {
            $otherKey = '{0}|{1}|{2}' -f $other.owning_process,
                $other.state, $other.tuple_key
            if ($otherPidKeys.Add($otherKey)) {
                $otherPid.Add($other)
            }
        }
        $ownedActive = @($connections | Where-Object {
            [int]$_.owning_process -eq $Process.Id -and
            [string]$_.state -in @('SynSent', 'Established')
        })
        $ownedActiveV4 = @($ownedActive | Where-Object family -eq 'IPv4')
        $ownedActiveV6 = @($ownedActive | Where-Object family -eq 'IPv6')
        if ($ownedActive.Count -gt 1) {
            $duplicateTargetObservationCount++
            $duplicateTargetObservations.Add(
                [pscustomobject][ordered]@{
                    captured_at_utc = Get-LabUtcTimestamp
                    active_connections = @($ownedActive)
                }
            )
        }
        if ($ownedActive.Count -eq 1 -and
            $ownedActiveV4.Count -eq 1 -and
            [string]$ownedActiveV4[0].state -ceq 'Established') {
            $selected = $ownedActiveV4[0]
        } else {
            $selected = $null
        }

        try {
            $part = Get-ChildItem -LiteralPath $TempPath -File `
                -Filter '*.part' -ErrorAction Stop |
                Sort-Object LastWriteTimeUtc -Descending |
                Select-Object -First 1
        } catch {
            throw 'I03_COLLECTOR::TEMP_ENUMERATION_FAILED'
        }
        if ($null -ne $part) {
            if ($null -ne $lastPartWrite -and
                $part.LastWriteTimeUtc -gt $lastPartWrite) {
                $progress = $true
            }
            $lastPartWrite = $part.LastWriteTimeUtc
        }
        $hello = Get-I03HelloEvidence -NodePath $NodePath `
            -ExpectedIPv6 $peerV6Text `
            -SnapshotRoot (Split-Path -Parent $SamplesPath)

        $now = [DateTime]::UtcNow
        $health = $null
        if ($now -ge $nextHealth) {
            $api = Get-I03ApiProbe -Port $WebPort -AllowControlledEd2k
            $ui = Get-I03UiProbe -Process $Process
            $apiCount++
            if (-not $api.available -or -not $api.isolation_valid) {
                $apiFailures++
            }
            $apiMaxMs = [Math]::Max($apiMaxMs, [Int64]$api.duration_ms)
            $uiCount++
            if (-not $ui.main_window_present -or
                -not $ui.message_pump_responsive) {
                $uiFailures++
            }
            $uiMaxMs = [Math]::Max($uiMaxMs, [Int64]$ui.duration_ms)
            $health = [ordered]@{ api = $api; ui = $ui }
            $nextHealth = $now.AddSeconds(1)
        }
        $signature = (@($connections | ForEach-Object {
            '{0}:{1}:{2}:{3}' -f $_.owning_process, $_.state,
                $_.family, $_.tuple_key
        }) -join ';')
        if ($signature -ne $lastSignature -or $null -ne $health) {
            Add-I03JsonLine -Path $SamplesPath -Value ([ordered]@{
                schema = 'ese.v91.i03-prewarm-sample/v1'
                sample_number = ++$sample
                captured_at_utc = Get-LabUtcTimestamp
                connections = $connections
                process_socket_census = $processCensus
                process_socket_decision = $censusDecision
                transfer_progress = $progress
                hello = $hello
                health = $health
            })
            $lastSignature = $signature
        }

        if ($duplicateTargetObservationCount -gt 0 -or
            ($null -ne $selected -and $progress -and
            [bool]$hello.learned_public_ipv6_via_hello)) {
            Start-Sleep -Milliseconds 500
            break
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)

    $hello = Get-I03HelloEvidence -NodePath $NodePath `
        -ExpectedIPv6 $peerV6Text `
        -SnapshotRoot (Split-Path -Parent $SamplesPath) `
        -PersistSnapshots
    Assert-I03ControlledEd2kServerHealthy -Server $ControlledServer
    $finalConnections = @(Get-I03TargetConnections)
    $finalProcessCensus = Get-I03ProcessSocketCensus `
        -ProcessId $Process.Id
    if (-not [bool]$finalProcessCensus.collector_ok) {
        throw "I03_COLLECTOR::$($finalProcessCensus.collector_error_code)"
    }
    $finalCensusDecision = Get-I03CandidateSocketCensusDecision `
        -Census $finalProcessCensus -ProcessId $Process.Id `
        -TcpPort $TcpPort -UdpPort $UdpPort -WebPort $WebPort `
        -TargetAddresses $TargetAddresses -TargetPort $TargetPort `
        -ControlAddress $ControlAddress -ControlPort $ControlPort
    foreach ($unexpectedSocket in @($finalCensusDecision.unexpected_rows)) {
        $socketKey = '{0}|{1}|{2}|{3}|{4}|{5}' -f
            $unexpectedSocket.transport, $unexpectedSocket.state,
            $unexpectedSocket.local_address, $unexpectedSocket.local_port,
            $unexpectedSocket.remote_address, $unexpectedSocket.remote_port
        if ($unexpectedSocketKeys.Add($socketKey)) {
            $unexpectedSockets.Add($unexpectedSocket)
        }
    }
    foreach ($other in @($finalConnections | Where-Object {
        [int]$_.owning_process -ne $Process.Id -and
        [string]$_.state -in @('SynSent', 'Established')
    })) {
        $otherKey = '{0}|{1}|{2}' -f $other.owning_process,
            $other.state, $other.tuple_key
        if ($otherPidKeys.Add($otherKey)) {
            $otherPid.Add($other)
        }
    }
    $finalOwnedActive = @($finalConnections | Where-Object {
        [int]$_.owning_process -eq $Process.Id -and
        [string]$_.state -in @('SynSent', 'Established')
    })
    $finalOwnedV4 = @($finalOwnedActive | Where-Object family -eq 'IPv4')
    $finalOwnedV6 = @($finalOwnedActive | Where-Object family -eq 'IPv6')
    if ($finalOwnedActive.Count -gt 1) {
        $duplicateTargetObservationCount++
        $duplicateTargetObservations.Add(
            [pscustomobject][ordered]@{
                captured_at_utc = Get-LabUtcTimestamp
                active_connections = @($finalOwnedActive)
            }
        )
    }
    if ($finalOwnedActive.Count -eq 1 -and
        $finalOwnedV4.Count -eq 1 -and
        [string]$finalOwnedV4[0].state -ceq 'Established') {
        $selected = $finalOwnedV4[0]
    } else {
        $selected = $null
    }
    $socket = if ($null -ne $selected) {
        Get-I03SocketEvidence -Connection $selected `
            -ExpectedProcessId $Process.Id
    } else { $null }
    return [pscustomobject][ordered]@{
        complete = $duplicateTargetObservationCount -eq 0 -and
            $null -ne $selected -and $progress -and
            $null -ne $hello -and
            [bool]$hello.learned_public_ipv6_via_hello
        selected_connection = $selected
        socket = $socket
        final_connection_revalidation = [ordered]@{
            captured_at_utc = Get-LabUtcTimestamp
            current_owned_active_count = $finalOwnedActive.Count
            current_ipv4_active_count = $finalOwnedV4.Count
            current_ipv6_active_count = $finalOwnedV6.Count
            selected_tuple_current = $null -ne $selected
        }
        duplicate_target_observation_count =
            $duplicateTargetObservationCount
        duplicate_target_observations = @($duplicateTargetObservations)
        transfer_progress = $progress
        hello = $hello
        other_pid_connection_count = $otherPid.Count
        other_pid_connections = @($otherPid)
        process_socket_census = $finalProcessCensus
        process_socket_decision = $finalCensusDecision
        unexpected_socket_observation_count = $unexpectedSockets.Count
        unexpected_socket_observations = @($unexpectedSockets)
        api_probe_count = $apiCount
        api_failure_count = $apiFailures
        api_max_ms = $apiMaxMs
        ui_probe_count = $uiCount
        ui_failure_count = $uiFailures
        ui_max_ms = $uiMaxMs
        health_valid = $apiCount -gt 0 -and $apiFailures -eq 0 -and
            $apiMaxMs -lt 2000 -and $uiCount -gt 0 -and
            $uiFailures -eq 0 -and $uiMaxMs -lt 1000
    }
}

function Wait-I03PostRestartRoute {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][object]$ControlledServer,
        [Parameter(Mandatory = $true)][int]$WebPort,
        [Parameter(Mandatory = $true)][int]$TcpPort,
        [Parameter(Mandatory = $true)][int]$UdpPort,
        [Parameter(Mandatory = $true)][string[]]$TargetAddresses,
        [Parameter(Mandatory = $true)][int]$TargetPort,
        [Parameter(Mandatory = $true)][string]$ControlAddress,
        [Parameter(Mandatory = $true)][int]$ControlPort,
        [Parameter(Mandatory = $true)][string]$ExpectedFamily,
        [Parameter(Mandatory = $true)][string]$PrewarmTuple,
        [Parameter(Mandatory = $true)][string]$RestartAckPath,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][int]$ObservationSeconds,
        [Parameter(Mandatory = $true)][string]$SamplesPath
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $prewarmGone = $false
    $prewarmGoneAt = $null
    $selected = $null
    $selectedAt = $null
    $wrongSelected = $null
    $wrongSelectedAt = $null
    $stableSignature = ''
    $stableSince = $null
    $ambiguousSelectionObserved = $false
    $duplicateTargetObservationCount = 0
    $duplicateTargetObservations =
        [System.Collections.Generic.List[object]]::new()
    $wrongFamily = [System.Collections.Generic.List[object]]::new()
    $wrongFamilyKeys = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $otherPid = [System.Collections.Generic.List[object]]::new()
    $otherPidKeys = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $unexpectedSockets = [System.Collections.Generic.List[object]]::new()
    $unexpectedSocketKeys =
        [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
    $restartAck = $null
    $apiCount = 0
    $apiFailures = 0
    $apiMaxMs = 0L
    $uiCount = 0
    $uiFailures = 0
    $uiMaxMs = 0L
    $nextHealth = [DateTime]::UtcNow
    $lastSignature = ''
    $sample = 0

    do {
        $now = [DateTime]::UtcNow
        $Process.Refresh()
        if ($Process.HasExited) {
            throw 'Client exited during post-restart route observation'
        }
        Assert-I03ControlledEd2kServerHealthy -Server $ControlledServer
        if ($null -eq $restartAck -and
            (Test-Path -LiteralPath $RestartAckPath -PathType Leaf)) {
            $restartAck = Get-Content -LiteralPath $RestartAckPath -Raw |
                ConvertFrom-Json -ErrorAction Stop
        }
        $connections = @(Get-I03TargetConnections)
        $processCensus = Get-I03ProcessSocketCensus -ProcessId $Process.Id
        if (-not [bool]$processCensus.collector_ok) {
            throw "I03_COLLECTOR::$($processCensus.collector_error_code)"
        }
        $censusDecision = Get-I03CandidateSocketCensusDecision `
            -Census $processCensus -ProcessId $Process.Id `
            -TcpPort $TcpPort -UdpPort $UdpPort -WebPort $WebPort `
            -TargetAddresses $TargetAddresses -TargetPort $TargetPort `
            -ControlAddress $ControlAddress -ControlPort $ControlPort
        foreach ($unexpectedSocket in @($censusDecision.unexpected_rows)) {
            $socketKey = '{0}|{1}|{2}|{3}|{4}|{5}' -f
                $unexpectedSocket.transport, $unexpectedSocket.state,
                $unexpectedSocket.local_address,
                $unexpectedSocket.local_port,
                $unexpectedSocket.remote_address,
                $unexpectedSocket.remote_port
            if ($unexpectedSocketKeys.Add($socketKey)) {
                $unexpectedSockets.Add($unexpectedSocket)
            }
        }
        $prewarmPresent = @($connections | Where-Object {
            [int]$_.owning_process -eq $Process.Id -and
            [string]$_.tuple_key -eq $PrewarmTuple -and
            [string]$_.state -in @('SynSent', 'Established')
        }).Count -gt 0
        if (-not $prewarmPresent -and -not $prewarmGone) {
            $prewarmGone = $true
            $prewarmGoneAt = $now
        }
        foreach ($connection in @($connections | Where-Object {
            [string]$_.state -in @('SynSent', 'Established')
        })) {
            if ([int]$connection.owning_process -ne $Process.Id) {
                $otherKey = '{0}|{1}|{2}' -f
                    $connection.owning_process, $connection.state,
                    $connection.tuple_key
                if ($otherPidKeys.Add($otherKey)) {
                    $otherPid.Add($connection)
                }
                continue
            }
            if (-not $prewarmGone) {
                continue
            }
            if ([string]$connection.family -ne $ExpectedFamily) {
                $wrongKey = '{0}|{1}' -f $connection.state,
                    $connection.tuple_key
                if ($wrongFamilyKeys.Add($wrongKey)) {
                    $wrongFamily.Add($connection)
                }
            }
        }
        $currentActive = @(
            if ($prewarmGone) {
                $connections | Where-Object {
                    [int]$_.owning_process -eq $Process.Id -and
                    [string]$_.state -in @('SynSent', 'Established')
                }
            }
        )
        $currentExpected = @($currentActive | Where-Object {
            [string]$_.family -eq $ExpectedFamily
        })
        $currentWrong = @($currentActive | Where-Object {
            [string]$_.family -ne $ExpectedFamily
        })
        if ($currentActive.Count -gt 1) {
            $ambiguousSelectionObserved = $true
            $duplicateTargetObservationCount++
            $duplicateTargetObservations.Add(
                [pscustomobject][ordered]@{
                    captured_at_utc = Get-LabUtcTimestamp
                    active_connections = @($currentActive)
                }
            )
        }
        $currentStableSignature = @(
            $currentActive | ForEach-Object {
                '{0}|{1}' -f [string]$_.state, [string]$_.tuple_key
            } | Sort-Object
        ) -join ';'
        if ($currentStableSignature) {
            if ($currentStableSignature -ne $stableSignature) {
                $stableSignature = $currentStableSignature
                $stableSince = $now
            }
        } else {
            $stableSignature = ''
            $stableSince = $null
        }
        $selected = if ($currentActive.Count -eq 1 -and
            $currentExpected.Count -eq 1 -and
            [string]$currentExpected[0].state -ceq 'Established') {
            $currentExpected[0]
        } else { $null }
        $wrongSelected = if ($currentActive.Count -eq 1 -and
            $currentWrong.Count -eq 1 -and
            [string]$currentWrong[0].state -ceq 'Established') {
            $currentWrong[0]
        } else { $null }
        $selectedAt = if ($null -ne $selected) {
            $stableSince
        } else { $null }
        $wrongSelectedAt = if ($null -ne $wrongSelected) {
            $stableSince
        } else { $null }

        $health = $null
        if ($now -ge $nextHealth) {
            $api = Get-I03ApiProbe -Port $WebPort -AllowControlledEd2k
            $ui = Get-I03UiProbe -Process $Process
            $apiCount++
            if (-not $api.available -or -not $api.isolation_valid) {
                $apiFailures++
            }
            $apiMaxMs = [Math]::Max($apiMaxMs, [Int64]$api.duration_ms)
            $uiCount++
            if (-not $ui.main_window_present -or
                -not $ui.message_pump_responsive) {
                $uiFailures++
            }
            $uiMaxMs = [Math]::Max($uiMaxMs, [Int64]$ui.duration_ms)
            $health = [ordered]@{ api = $api; ui = $ui }
            $nextHealth = $now.AddSeconds(1)
        }
        $connectionSignature = (@($connections | ForEach-Object {
            '{0}:{1}:{2}:{3}' -f $_.owning_process, $_.state,
                $_.family, $_.tuple_key
        }) -join ';')
        $censusSignature = (@(
            @($processCensus.tcp_rows) + @($processCensus.udp_rows) |
                ForEach-Object {
                    '{0}:{1}:{2}:{3}:{4}:{5}' -f $_.transport,
                        $_.state, $_.local_address, $_.local_port,
                        $_.remote_address, $_.remote_port
                } | Sort-Object
        ) -join ';')
        $signature = "$connectionSignature|$censusSignature"
        if ($signature -ne $lastSignature -or $null -ne $health) {
            Add-I03JsonLine -Path $SamplesPath -Value ([ordered]@{
                schema = 'ese.v91.i03-route-sample/v1'
                sample_number = ++$sample
                captured_at_utc = Get-LabUtcTimestamp
                prewarm_gone = $prewarmGone
                expected_family = $ExpectedFamily
                connections = $connections
                process_socket_census = $processCensus
                process_socket_decision = $censusDecision
                restart_ack_seen = $null -ne $restartAck
                current_established_signature =
                    $currentStableSignature
                current_established_since_utc = if (
                    $null -eq $stableSince
                ) { $null } else { $stableSince.ToString('o') }
                health = $health
            })
            $lastSignature = $signature
        }
        if ($duplicateTargetObservationCount -gt 0 -or
            ($null -ne $stableSince -and $null -ne $restartAck -and
            ($now - $stableSince).TotalSeconds -ge $ObservationSeconds)) {
            break
        }
        Start-Sleep -Milliseconds 75
    } while ([DateTime]::UtcNow -lt $deadline)

    $Process.Refresh()
    if ($Process.HasExited) {
        throw 'Client exited during post-restart route observation'
    }
    Assert-I03ControlledEd2kServerHealthy -Server $ControlledServer
    $finalConnections = @(Get-I03TargetConnections)
    $finalProcessCensus = Get-I03ProcessSocketCensus `
        -ProcessId $Process.Id
    if (-not [bool]$finalProcessCensus.collector_ok) {
        throw "I03_COLLECTOR::$($finalProcessCensus.collector_error_code)"
    }
    $finalCensusDecision = Get-I03CandidateSocketCensusDecision `
        -Census $finalProcessCensus -ProcessId $Process.Id `
        -TcpPort $TcpPort -UdpPort $UdpPort -WebPort $WebPort `
        -TargetAddresses $TargetAddresses -TargetPort $TargetPort `
        -ControlAddress $ControlAddress -ControlPort $ControlPort
    foreach ($unexpectedSocket in @($finalCensusDecision.unexpected_rows)) {
        $socketKey = '{0}|{1}|{2}|{3}|{4}|{5}' -f
            $unexpectedSocket.transport, $unexpectedSocket.state,
            $unexpectedSocket.local_address, $unexpectedSocket.local_port,
            $unexpectedSocket.remote_address, $unexpectedSocket.remote_port
        if ($unexpectedSocketKeys.Add($socketKey)) {
            $unexpectedSockets.Add($unexpectedSocket)
        }
    }
    foreach ($other in @($finalConnections | Where-Object {
        [int]$_.owning_process -ne $Process.Id -and
        [string]$_.state -in @('SynSent', 'Established')
    })) {
        $otherKey = '{0}|{1}|{2}' -f $other.owning_process,
            $other.state, $other.tuple_key
        if ($otherPidKeys.Add($otherKey)) {
            $otherPid.Add($other)
        }
    }
    $finalActive = @(
        if ($prewarmGone) {
            $finalConnections | Where-Object {
                [int]$_.owning_process -eq $Process.Id -and
                [string]$_.state -in @('SynSent', 'Established')
            }
        }
    )
    $finalEstablished = @($finalActive | Where-Object {
        [string]$_.state -eq 'Established'
    })
    $finalExpectedActive = @($finalActive | Where-Object {
        [string]$_.family -eq $ExpectedFamily
    })
    $finalWrongActive = @($finalActive | Where-Object {
        [string]$_.family -ne $ExpectedFamily
    })
    $finalSignature = @(
        $finalActive | ForEach-Object {
            '{0}|{1}' -f [string]$_.state, [string]$_.tuple_key
        } | Sort-Object
    ) -join ';'
    $finalMatchesObservedWindow = $finalSignature -and
        $finalSignature -eq $stableSignature
    if ($finalSignature -ne $stableSignature) {
        $stableSignature = $finalSignature
        $stableSince = if ($finalSignature) {
            [DateTime]::UtcNow
        } else { $null }
    }
    if ($finalActive.Count -gt 1) {
        $ambiguousSelectionObserved = $true
        $duplicateTargetObservationCount++
        $duplicateTargetObservations.Add(
            [pscustomobject][ordered]@{
                captured_at_utc = Get-LabUtcTimestamp
                active_connections = @($finalActive)
            }
        )
    }
    $selected = if ($finalActive.Count -eq 1 -and
        $finalExpectedActive.Count -eq 1 -and
        [string]$finalExpectedActive[0].state -ceq 'Established') {
        $finalExpectedActive[0]
    } else { $null }
    $wrongSelected = if ($finalActive.Count -eq 1 -and
        $finalWrongActive.Count -eq 1 -and
        [string]$finalWrongActive[0].state -ceq 'Established') {
        $finalWrongActive[0]
    } else { $null }
    $selectedAt = if ($null -ne $selected) {
        $stableSince
    } else { $null }
    $wrongSelectedAt = if ($null -ne $wrongSelected) {
        $stableSince
    } else { $null }
    $currentSocketEvidence = @(
        $finalEstablished | ForEach-Object {
            Get-I03SocketEvidence -Connection $_ `
                -ExpectedProcessId $Process.Id
        }
    )
    $socket = if ($null -ne $selected) {
        Get-I03SocketEvidence -Connection $selected `
            -ExpectedProcessId $Process.Id
    } else { $null }
    $wrongSocket = if ($null -ne $wrongSelected) {
        Get-I03SocketEvidence -Connection $wrongSelected `
            -ExpectedProcessId $Process.Id
    } else { $null }
    return [pscustomobject][ordered]@{
        prewarm_tuple = $PrewarmTuple
        prewarm_disappeared = $prewarmGone
        prewarm_disappeared_at_utc = if ($null -eq $prewarmGoneAt) {
            $null
        } else { $prewarmGoneAt.ToString('o') }
        restart_ack = $restartAck
        expected_family = $ExpectedFamily
        selected_connection = $selected
        selected_at_utc = if ($null -eq $selectedAt) {
            $null
        } else { $selectedAt.ToString('o') }
        socket = $socket
        wrong_family_selected_connection = $wrongSelected
        wrong_family_selected_at_utc = if ($null -eq $wrongSelectedAt) {
            $null
        } else { $wrongSelectedAt.ToString('o') }
        wrong_family_socket = $wrongSocket
        current_established_connections = @($finalEstablished)
        current_active_target_connections = @($finalActive)
        current_socket_evidence = @($currentSocketEvidence)
        final_connection_revalidation = [ordered]@{
            captured_at_utc = Get-LabUtcTimestamp
            signature = $finalSignature
            matches_continuous_observation_window =
                [bool]$finalMatchesObservedWindow
            established_count = @($finalEstablished).Count
            active_target_count = @($finalActive).Count
            expected_family_active_count = $finalExpectedActive.Count
            wrong_family_active_count = $finalWrongActive.Count
        }
        ambiguous_family_selection = $ambiguousSelectionObserved
        duplicate_target_observation_count =
            $duplicateTargetObservationCount
        duplicate_target_observations = @($duplicateTargetObservations)
        wrong_family_observation_count = $wrongFamily.Count
        wrong_family_observations = @($wrongFamily)
        other_pid_connection_count = $otherPid.Count
        other_pid_connections = @($otherPid)
        process_socket_census = $finalProcessCensus
        process_socket_decision = $finalCensusDecision
        unexpected_socket_observation_count = $unexpectedSockets.Count
        unexpected_socket_observations = @($unexpectedSockets)
        stable_observation_seconds = if ($null -eq $stableSince -or
            -not $finalSignature) {
            0
        } else {
            [Math]::Round(
                ([DateTime]::UtcNow - $stableSince).TotalSeconds, 3
            )
        }
        api_probe_count = $apiCount
        api_failure_count = $apiFailures
        api_max_ms = $apiMaxMs
        ui_probe_count = $uiCount
        ui_failure_count = $uiFailures
        ui_max_ms = $uiMaxMs
        health_valid = $apiCount -gt 0 -and $apiFailures -eq 0 -and
            $apiMaxMs -lt 2000 -and $uiCount -gt 0 -and
            $uiFailures -eq 0 -and $uiMaxMs -lt 1000
    }
}

function Enable-I03ControlledEd2kProfile {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][string]$ServerAddress,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1024, 65535)][int]$ServerPort,
        [Parameter(Mandatory = $true)][string]$RunNonce,
        [Parameter(Mandatory = $true)][string]$Policy,
        [Parameter(Mandatory = $true)][int]$IPv6Mode,
        [Parameter(Mandatory = $true)][int]$WebPort
    )

    $preferences = Join-Path $NodePath 'config\preferences.ini'
    foreach ($entry in ([ordered]@{
        Autoconnect = '1'
        NetworkKademlia = '0'
        AutoConnectStaticOnly = '1'
        Reconnect = '1'
        Serverlist = '0'
        UpdateNotifyTestClient = '0'
        AddServersFromServer = '0'
        AddServersFromClient = '0'
        FilterBadIPs = '0'
        FilterServersByIP = '0'
        ServerKeepAliveTimeout = '60000'
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'eMule' `
            -Key $entry.Key -Value $entry.Value
    }
    foreach ($entry in ([ordered]@{
        NetworkED2K = '1'
        CryptLayerRequested = '0'
        CryptLayerRequired = '0'
        CryptLayerSupported = '0'
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'Connection' `
            -Key $entry.Key -Value $entry.Value
    }

    $config = Join-Path $NodePath 'config'
    foreach ($name in @(
        'server.met', 'server_met.old', 'server_met.download',
        'server_met.old.bak'
    )) {
        $path = Join-Path $config $name
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        }
    }
    $staticPath = Join-Path $config 'staticservers.dat'
    $line = '{0}:{1},0,eSE-I03-{2}-{3}' -f
        $ServerAddress, $ServerPort, $RunNonce, $Policy
    [IO.File]::WriteAllText(
        $staticPath, ($line + "`r`n"),
        (New-Object Text.UnicodeEncoding($false, $true))
    )
    $effectiveContract = Assert-I03PreferenceContract `
        -PreferencesPath $preferences -IPv6Mode $IPv6Mode `
        -IPv6BindAddress '::' -WebPort $WebPort -NetworkEd2k 1
    return [pscustomobject][ordered]@{
        endpoint = "$ServerAddress`:$ServerPort"
        endpoint_scope = 'same-host assigned physical IPv4'
        staticservers_path = $staticPath
        staticservers_sha256 = Get-LabSha256 -Path $staticPath
        preferences_sha256 = Get-LabSha256 -Path $preferences
        network_ed2k = $true
        network_kad = $false
        auto_connect_static_only = $true
        filter_lan_ips = $false
        third_party_server_files_removed = $true
        effective_configuration = $effectiveContract
    }
}

function New-I03Ed2kFrame {
    param(
        [Parameter(Mandatory = $true)][byte]$Opcode,
        [AllowEmptyCollection()][byte[]]$Payload = @()
    )

    if ($Payload.Length -gt 16777215) {
        throw 'I03_ED2K_CODEC::PAYLOAD_TOO_LARGE'
    }
    $packetLength = [uint32]($Payload.Length + 1)
    $frame = New-Object byte[] (6 + $Payload.Length)
    $frame[0] = 0xE3
    $frame[1] = [byte]($packetLength -band 0xFF)
    $frame[2] = [byte](($packetLength -shr 8) -band 0xFF)
    $frame[3] = [byte](($packetLength -shr 16) -band 0xFF)
    $frame[4] = [byte](($packetLength -shr 24) -band 0xFF)
    $frame[5] = $Opcode
    if ($Payload.Length -gt 0) {
        [Array]::Copy($Payload, 0, $frame, 6, $Payload.Length)
    }
    return ,$frame
}

function New-I03Ed2kIdChangeFrame {
    param([uint32]$ClientId = [uint32]0x01000001)

    $payload = New-Object byte[] 4
    $payload[0] = [byte]($ClientId -band 0xFF)
    $payload[1] = [byte](($ClientId -shr 8) -band 0xFF)
    $payload[2] = [byte](($ClientId -shr 16) -band 0xFF)
    $payload[3] = [byte](($ClientId -shr 24) -band 0xFF)
    return ,(New-I03Ed2kFrame -Opcode 0x40 -Payload $payload)
}

function Test-I03Ed2kLoginRequestFrame {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()][byte[]]$Frame
    )

    $result = [ordered]@{
        schema = 'ese.v91.i03-ed2k-loginrequest-codec/v1'
        valid = $false
        error_code = 'TRUNCATED_HEADER'
        protocol = if ($Frame.Length -gt 0) { [int]$Frame[0] } else { -1 }
        opcode = if ($Frame.Length -gt 5) { [int]$Frame[5] } else { -1 }
        packet_length = 0L
        payload_length = 0
        payload_sha256 = ''
        advertised_tcp_port = 0
    }
    if ($Frame.Length -lt 6) { return [pscustomobject]$result }
    $packetLength = [uint32]$Frame[1] -bor
        ([uint32]$Frame[2] -shl 8) -bor
        ([uint32]$Frame[3] -shl 16) -bor
        ([uint32]$Frame[4] -shl 24)
    $result.packet_length = [Int64]$packetLength
    if ($Frame[0] -ne 0xE3) {
        $result.error_code = 'WRONG_PROTOCOL'
        return [pscustomobject]$result
    }
    if ($Frame[5] -ne 0x01) {
        $result.error_code = 'WRONG_OPCODE'
        return [pscustomobject]$result
    }
    if ($packetLength -lt 1) {
        $result.error_code = 'INVALID_PACKET_LENGTH'
        return [pscustomobject]$result
    }
    if ($packetLength -gt 1048576) {
        $result.error_code = 'OVERSIZED_PACKET'
        return [pscustomobject]$result
    }
    $expectedFrameLength = [Int64]$packetLength + 5
    if ([Int64]$Frame.Length -lt $expectedFrameLength) {
        $result.error_code = 'TRUNCATED_PAYLOAD'
        return [pscustomobject]$result
    }
    if ([Int64]$Frame.Length -gt $expectedFrameLength) {
        $result.error_code = 'TRAILING_BYTES'
        return [pscustomobject]$result
    }
    $payloadLength = [int]$packetLength - 1
    $result.payload_length = $payloadLength
    if ($payloadLength -lt 22) {
        $result.error_code = 'LOGIN_PAYLOAD_TOO_SHORT'
        return [pscustomobject]$result
    }
    $payload = New-Object byte[] $payloadLength
    [Array]::Copy($Frame, 6, $payload, 0, $payloadLength)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $result.payload_sha256 = ([BitConverter]::ToString(
            $sha.ComputeHash($payload)
        )).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
    $result.advertised_tcp_port = [int](
        [uint16]$payload[20] -bor ([uint16]$payload[21] -shl 8)
    )
    $result.valid = $true
    $result.error_code = 'NONE'
    return [pscustomobject]$result
}

function Start-I03ControlledEd2kServer {
    param(
        [Parameter(Mandatory = $true)][string]$EvidencePath,
        [Parameter(Mandatory = $true)][string]$ListenAddress,
        [Parameter(Mandatory = $true)][string]$ExpectedClientAddress,
        [Parameter(Mandatory = $true)][string]$RunNonce,
        [Parameter(Mandatory = $true)][string]$Policy,
        [Parameter(Mandatory = $true)][int[]]$ForbiddenPorts
    )

    $listenIp = [Net.IPAddress]::Parse($ListenAddress)
    if ($listenIp.AddressFamily -ne
        [Net.Sockets.AddressFamily]::InterNetwork -or
        [Net.IPAddress]::IsLoopback($listenIp)) {
        throw 'Controlled eD2K server requires an assigned non-loopback IPv4'
    }
    $forbidden = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($forbiddenPort in $ForbiddenPorts) {
        if ($forbiddenPort -lt 1 -or $forbiddenPort -gt 65535) {
            throw 'I03_PORT_ALLOCATION::INVALID_FORBIDDEN_PORT'
        }
        [void]$forbidden.Add([int]$forbiddenPort)
    }
    $listener = $null
    $port = 0
    for ($attempt = 1; $attempt -le 64; $attempt++) {
        $candidateListener =
            [Net.Sockets.TcpListener]::new($listenIp, 0)
        $candidateListener.Server.ExclusiveAddressUse = $true
        try {
            $candidateListener.Start(1)
            $candidateEndpoint = [Net.IPEndPoint]
                $candidateListener.LocalEndpoint
            $candidatePort = [int]$candidateEndpoint.Port
            if ($forbidden.Contains($candidatePort)) {
                $candidateListener.Stop()
                continue
            }
            $listener = $candidateListener
            $port = $candidatePort
            break
        } catch {
            $candidateListener.Stop()
            throw
        }
    }
    if ($null -eq $listener -or $port -le 0) {
        throw 'I03_PORT_ALLOCATION::NO_NONCOLLIDING_PORT'
    }
    $state =
        [System.Collections.Concurrent.ConcurrentDictionary[string,object]]::new()
    $state['phase'] = 'listening'
    $state['stop_requested'] = $false
    $state['logged_in'] = $false
    $state['reply_sent'] = $false
    $state['error_kind'] = 'none'
    $state['error_code'] = 'NONE'
    $state['candidate_attributed'] = $false
    $state['frames_received'] = 0
    $state['listen_port'] = $port
    $state['high_id'] = [uint32]0x01000001

    $state['listen_address'] = $ListenAddress
    $state['expected_client_address'] = $ExpectedClientAddress

    $serverBody = {
        param(
            $Listener, $State, $ResultPath, $Nonce, $PolicyName,
            $AllowedClientAddress, $LoginCodecSource,
            $FrameCodecSource, $IdChangeCodecSource
        )

        Set-Item -Path Function:\Test-I03Ed2kLoginRequestFrame `
            -Value ([ScriptBlock]::Create($LoginCodecSource))
        Set-Item -Path Function:\New-I03Ed2kFrame `
            -Value ([ScriptBlock]::Create($FrameCodecSource))
        Set-Item -Path Function:\New-I03Ed2kIdChangeFrame `
            -Value ([ScriptBlock]::Create($IdChangeCodecSource))

        function Read-ExactBytes {
            param(
                [Parameter(Mandatory = $true)]
                [Net.Sockets.NetworkStream]$Stream,
                [Parameter(Mandatory = $true)][int]$Count
            )
            $buffer = New-Object byte[] $Count
            $offset = 0
            while ($offset -lt $Count) {
                $read = $Stream.Read($buffer, $offset, $Count - $offset)
                if ($read -le 0) {
                    throw "Controlled server TCP stream closed after $offset/$Count bytes"
                }
                $offset += $read
            }
            return $buffer
        }

        $client = $null
        $stream = $null
        $loginAt = ''
        $stoppedAt = ''
        try {
            $State['phase'] = 'accepting'
            $client = $Listener.AcceptTcpClient()
            $State['client'] = $client
            $remote = [Net.IPEndPoint]$client.Client.RemoteEndPoint
            if ($remote.Address.ToString() -ne $AllowedClientAddress) {
                throw 'I03_EXTERNAL_CONTAMINATION::UNEXPECTED_SOURCE_ADDRESS'
            }
            $State['accepted_remote'] = $remote.ToString()
            $identityDeadline = [DateTime]::UtcNow.AddSeconds(5)
            while (-not $State.ContainsKey('expected_client_process_id') -and
                [DateTime]::UtcNow -lt $identityDeadline) {
                Start-Sleep -Milliseconds 10
            }
            if (-not $State.ContainsKey('expected_client_process_id')) {
                throw 'I03_FIXTURE_INTERNAL::EXPECTED_CLIENT_PID_MISSING'
            }
            $expectedPid = [int]$State['expected_client_process_id']
            $reverseRows = @()
            $reverseDeadline = [DateTime]::UtcNow.AddSeconds(5)
            do {
                try {
                    $allTcpRows = @(
                        Get-NetTCPConnection -ErrorAction Stop
                    )
                    $reverseRows = @($allTcpRows | Where-Object {
                        [string]$_.State -eq 'Established' -and
                        ([Net.IPAddress]::Parse(
                            [string]$_.LocalAddress
                        )).ToString() -eq $AllowedClientAddress -and
                        [int]$_.LocalPort -eq [int]$remote.Port -and
                        ([Net.IPAddress]::Parse(
                            [string]$_.RemoteAddress
                        )).ToString() -eq
                            [string]$State['listen_address'] -and
                        [int]$_.RemotePort -eq
                            [int]$State['listen_port']
                    })
                } catch {
                    throw 'I03_COLLECTOR::SERVER_REVERSE_TUPLE_QUERY_FAILED'
                }
                $expectedPidRows = @($reverseRows | Where-Object {
                    [int]$_.OwningProcess -eq $expectedPid
                })
                if ($reverseRows.Count -gt 1 -or
                    ($reverseRows.Count -eq 1 -and
                    $expectedPidRows.Count -ne 1)) {
                    throw 'I03_EXTERNAL_CONTAMINATION::REVERSE_TUPLE_AMBIGUOUS'
                }
                if ($reverseRows.Count -eq 1) { break }
                Start-Sleep -Milliseconds 50
            } while ([DateTime]::UtcNow -lt $reverseDeadline)
            if ($reverseRows.Count -ne 1 -or
                $expectedPidRows.Count -ne 1) {
                throw 'I03_EXTERNAL_CONTAMINATION::REVERSE_TUPLE_NOT_OWNED'
            }
            $State['candidate_attributed'] = $true
            $State['attributed_process_id'] = $expectedPid
            $State['attributed_local_port'] = [int]$remote.Port
            $stream = $client.GetStream()
            $stream.ReadTimeout = 30000
            try {
                $header = Read-ExactBytes -Stream $stream -Count 6
            } catch {
                throw 'I03_CANDIDATE_PROTOCOL::TRUNCATED_HEADER'
            }
            $packetLength = [uint32]$header[1] -bor
                ([uint32]$header[2] -shl 8) -bor
                ([uint32]$header[3] -shl 16) -bor
                ([uint32]$header[4] -shl 24)
            $headerCodec = Test-I03Ed2kLoginRequestFrame -Frame $header
            if ([string]$headerCodec.error_code -ne
                    'TRUNCATED_PAYLOAD') {
                throw "I03_CANDIDATE_PROTOCOL::$($headerCodec.error_code)"
            }
            $payload = @()
            if ($packetLength -ge 1 -and $packetLength -le 1048576) {
                try {
                    $payload = Read-ExactBytes -Stream $stream `
                        -Count ([int]$packetLength - 1)
                } catch {
                    throw 'I03_CANDIDATE_PROTOCOL::TRUNCATED_PAYLOAD'
                }
            }
            $frame = New-Object byte[] (6 + $payload.Length)
            [Array]::Copy($header, 0, $frame, 0, 6)
            if ($payload.Length -gt 0) {
                [Array]::Copy($payload, 0, $frame, 6, $payload.Length)
            }
            $loginCodec = Test-I03Ed2kLoginRequestFrame -Frame $frame
            if (-not [bool]$loginCodec.valid) {
                throw "I03_CANDIDATE_PROTOCOL::$($loginCodec.error_code)"
            }
            $State['login_protocol'] = [int]$loginCodec.protocol
            $State['login_opcode'] = [int]$loginCodec.opcode
            $State['login_payload_bytes'] = [int]$loginCodec.payload_length
            $State['login_payload_sha256'] =
                [string]$loginCodec.payload_sha256
            $State['login_advertised_tcp_port'] =
                [int]$loginCodec.advertised_tcp_port
            $loginAt = [DateTime]::UtcNow.ToString('o')

            $idChangeFrame = New-I03Ed2kIdChangeFrame
            try {
                $stream.Write($idChangeFrame, 0, $idChangeFrame.Length)
                $stream.Flush()
            } catch {
                throw 'I03_CANDIDATE_TRANSPORT::IDCHANGE_WRITE_FAILED'
            }
            $State['reply_sent'] = $true
            $State['logged_in'] = $true
            $State['phase'] = 'connected'
            $State['login_at_utc'] = $loginAt
            $stream.ReadTimeout = 2000
            $nextStatus = [DateTime]::UtcNow.AddSeconds(10)

            while (-not [bool]$State['stop_requested']) {
                if ($stream.DataAvailable) {
                    try {
                        $nextHeader = Read-ExactBytes -Stream $stream -Count 6
                    } catch {
                        throw 'I03_CANDIDATE_TRANSPORT::FOLLOWUP_HEADER_READ_FAILED'
                    }
                    $nextLength = [BitConverter]::ToUInt32($nextHeader, 1)
                    if ($nextHeader[0] -ne 0xE3 -or
                        $nextLength -lt 1 -or $nextLength -gt 16777216) {
                        throw 'I03_CANDIDATE_PROTOCOL::INVALID_FOLLOWUP_FRAME'
                    }
                    $remaining = [int]$nextLength - 1
                    if ($remaining -gt 0) {
                        try {
                            $null = Read-ExactBytes -Stream $stream `
                                -Count $remaining
                        } catch {
                            throw 'I03_CANDIDATE_TRANSPORT::FOLLOWUP_PAYLOAD_READ_FAILED'
                        }
                    }
                    $State['frames_received'] =
                        [int]$State['frames_received'] + 1
                    $State['last_client_opcode'] = [int]$nextHeader[5]
                } elseif ([DateTime]::UtcNow -ge $nextStatus) {
                    $statusFrame = New-I03Ed2kFrame -Opcode 0x34 `
                        -Payload (New-Object byte[] 8)
                    try {
                        $stream.Write($statusFrame, 0, $statusFrame.Length)
                        $stream.Flush()
                    } catch {
                        throw 'I03_CANDIDATE_TRANSPORT::STATUS_WRITE_FAILED'
                    }
                    $State['status_frames_sent'] = if (
                        $State.ContainsKey('status_frames_sent')
                    ) {
                        [int]$State['status_frames_sent'] + 1
                    } else { 1 }
                    $nextStatus = [DateTime]::UtcNow.AddSeconds(10)
                } else {
                    Start-Sleep -Milliseconds 50
                }
            }
        } catch {
            if (-not [bool]$State['stop_requested']) {
                $errorText = [string]$_.Exception.Message
                if ($errorText -match
                    '^I03_CANDIDATE_PROTOCOL::([A-Z0-9_]+)$') {
                    $State['error_kind'] = 'candidate_protocol'
                    $State['error_code'] = [string]$Matches[1]
                } elseif ($errorText -match
                    '^I03_CANDIDATE_TRANSPORT::([A-Z0-9_]+)$') {
                    $State['error_kind'] = 'candidate_transport'
                    $State['error_code'] = [string]$Matches[1]
                } elseif ($errorText -match
                    '^I03_EXTERNAL_CONTAMINATION::([A-Z0-9_]+)$') {
                    $State['error_kind'] = 'external_contamination'
                    $State['error_code'] = [string]$Matches[1]
                } elseif ($errorText -match
                    '^I03_COLLECTOR::([A-Z0-9_]+)$') {
                    $State['error_kind'] = 'collector'
                    $State['error_code'] = [string]$Matches[1]
                } elseif ($errorText -match
                    '^I03_FIXTURE_INTERNAL::([A-Z0-9_]+)$') {
                    $State['error_kind'] = 'fixture_internal'
                    $State['error_code'] = [string]$Matches[1]
                } else {
                    $State['error_kind'] = 'fixture_internal'
                    $State['error_code'] = 'UNEXPECTED_SERVER_EXCEPTION'
                }
                $State['phase'] = 'error'
            }
        } finally {
            $stoppedAt = [DateTime]::UtcNow.ToString('o')
            if ($null -ne $stream) {
                try { $stream.Dispose() } catch {}
            }
            if ($null -ne $client) {
                try { $client.Dispose() } catch {}
            }
            try { $Listener.Stop() } catch {}
            if ([string]$State['phase'] -ne 'error') {
                $State['phase'] = 'stopped'
            }
            $State['stopped_at_utc'] = $stoppedAt
            $result = [ordered]@{
                schema = 'ese.v91.i03-controlled-ed2k-server/v1'
                run_nonce = $Nonce
                policy = $PolicyName
                listen_address = [string]$State['listen_address']
                listen_port = [int]$State['listen_port']
                high_id = [uint32]$State['high_id']
                login_at_utc = $loginAt
                stopped_at_utc = $stoppedAt
                phase = [string]$State['phase']
                logged_in = [bool]$State['logged_in']
                reply_sent = [bool]$State['reply_sent']
                candidate_attributed =
                    [bool]$State['candidate_attributed']
                attributed_process_id = if (
                    $State.ContainsKey('attributed_process_id')
                ) { [int]$State['attributed_process_id'] } else { 0 }
                login_protocol = if ($State.ContainsKey('login_protocol')) {
                    [int]$State['login_protocol']
                } else { $null }
                login_opcode = if ($State.ContainsKey('login_opcode')) {
                    [int]$State['login_opcode']
                } else { $null }
                login_payload_bytes = if (
                    $State.ContainsKey('login_payload_bytes')
                ) {
                    [int]$State['login_payload_bytes']
                } else { 0 }
                login_payload_sha256 = if (
                    $State.ContainsKey('login_payload_sha256')
                ) {
                    [string]$State['login_payload_sha256']
                } else { '' }
                login_advertised_tcp_port = if (
                    $State.ContainsKey('login_advertised_tcp_port')
                ) {
                    [int]$State['login_advertised_tcp_port']
                } else { 0 }
                frames_received = [int]$State['frames_received']
                status_frames_sent = if (
                    $State.ContainsKey('status_frames_sent')
                ) {
                    [int]$State['status_frames_sent']
                } else { 0 }
                accepted_remote = if (
                    $State.ContainsKey('accepted_remote')
                ) {
                    [string]$State['accepted_remote']
                } else { '' }
                error_kind = [string]$State['error_kind']
                error_code = [string]$State['error_code']
            }
            [IO.File]::WriteAllText(
                $ResultPath,
                ($result | ConvertTo-Json -Depth 16),
                (New-Object Text.UTF8Encoding($false))
            )
        }
    }

    $powershell = [PowerShell]::Create()
    $null = $powershell.AddScript($serverBody.ToString())
    $null = $powershell.AddArgument($listener)
    $null = $powershell.AddArgument($state)
    $null = $powershell.AddArgument($EvidencePath)
    $null = $powershell.AddArgument($RunNonce)
    $null = $powershell.AddArgument($Policy)
    $null = $powershell.AddArgument($ExpectedClientAddress)
    $null = $powershell.AddArgument(
        ${function:Test-I03Ed2kLoginRequestFrame}.ToString()
    )
    $null = $powershell.AddArgument(
        ${function:New-I03Ed2kFrame}.ToString()
    )
    $null = $powershell.AddArgument(
        ${function:New-I03Ed2kIdChangeFrame}.ToString()
    )
    $async = $powershell.BeginInvoke()

    return [pscustomobject][ordered]@{
        listener = $listener
        port = $port
        state = $state
        powershell = $powershell
        async = $async
        evidence_path = $EvidencePath
        started_at_utc = Get-LabUtcTimestamp
    }
}

function Assert-I03ControlledEd2kServerHealthy {
    param([Parameter(Mandatory = $true)][object]$Server)

    $kind = [string]$Server.state['error_kind']
    if (-not $kind -or $kind -eq 'none') { return }
    $attributed = [bool]$Server.state['candidate_attributed']
    if ($attributed -and $kind -eq 'candidate_protocol') {
        throw 'I03_PRODUCT::CONTROLLED_ED2K_PROTOCOL'
    }
    if ($attributed -and $kind -eq 'candidate_transport') {
        throw 'I03_PRODUCT::CONTROLLED_ED2K_TRANSPORT'
    }
    if ($kind -eq 'collector') {
        throw 'I03_COLLECTOR::SERVER_REVERSE_TUPLE_QUERY_FAILED'
    }
    if ($kind -eq 'external_contamination') {
        throw 'I03_FIXTURE::EXTERNAL_CONTAMINATION'
    }
    throw 'I03_FIXTURE::CONTROLLED_ED2K_SERVER_FAILED'
}

function Wait-I03ControlledEd2kLogin {
    param(
        [Parameter(Mandatory = $true)][object]$Server,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][int]$ExpectedTcpPort,
        [ValidateRange(5, 120)][int]$TimeoutSeconds = 60
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw 'Candidate exited before controlled eD2K login'
        }
        Assert-I03ControlledEd2kServerHealthy -Server $Server
        if ([bool]$Server.state['logged_in'] -and
            [bool]$Server.state['reply_sent']) {
            $census = Get-I03ProcessSocketCensus -ProcessId $Process.Id
            if (-not [bool]$census.collector_ok) {
                throw "I03_COLLECTOR::$($census.collector_error_code)"
            }
            $serverAddress = Get-I03NormalizedIp -Address `
                ([string]$Server.state['listen_address'])
            $connections = @($census.tcp_rows | Where-Object {
                [string]$_.state -eq 'Established' -and
                (Get-I03NormalizedIp -Address `
                    ([string]$_.remote_address)) -eq $serverAddress -and
                [int]$_.remote_port -eq $Server.port
            })
            if ($connections.Count -ne 1 -or
                -not [bool]$Server.state['candidate_attributed'] -or
                [int]$Server.state['attributed_process_id'] -ne $Process.Id) {
                throw 'I03_FIXTURE::EXTERNAL_CONTAMINATION'
            }
            if ([int]$Server.state['login_protocol'] -ne 0xE3 -or
                [int]$Server.state['login_opcode'] -ne 0x01 -or
                [int]$Server.state['login_payload_bytes'] -lt 22 -or
                [int]$Server.state['login_advertised_tcp_port'] -ne
                    $ExpectedTcpPort) {
                throw 'I03_PRODUCT::CONTROLLED_ED2K_PROTOCOL'
            }
            if ($connections.Count -eq 1) {
                return [pscustomobject][ordered]@{
                    connected = $true
                    server_address =
                        [string]$Server.state['listen_address']
                    server_port = $Server.port
                    client_process_id = $Process.Id
                    client_local_address =
                        Get-I03NormalizedIp -Address `
                            ([string]$connections[0].local_address)
                    client_local_port = [int]$connections[0].local_port
                    login_protocol = [int]$Server.state['login_protocol']
                    login_opcode = [int]$Server.state['login_opcode']
                    login_payload_bytes =
                        [int]$Server.state['login_payload_bytes']
                    login_payload_sha256 =
                        [string]$Server.state['login_payload_sha256']
                    advertised_tcp_port =
                        [int]$Server.state['login_advertised_tcp_port']
                    assigned_high_id = [uint32]$Server.state['high_id']
                    endpoint_is_same_host_physical = $true
                }
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Timed out proving the same-host physical-IP controlled eD2K login'
}

function Stop-I03ControlledEd2kServer {
    param([AllowNull()][object]$Server)

    if ($null -eq $Server) {
        return [pscustomobject]@{
            stopped = $true
            error = $null
            evidence = $null
        }
    }
    $errorText = $null
    try {
        $Server.state['stop_requested'] = $true
        if ($Server.state.ContainsKey('client')) {
            try { $Server.state['client'].Close() } catch {}
        }
        try { $Server.listener.Stop() } catch {}
        if (-not $Server.async.AsyncWaitHandle.WaitOne(
            [TimeSpan]::FromSeconds(10)
        )) {
            $Server.powershell.Stop()
        }
        try { $null = $Server.powershell.EndInvoke($Server.async) } catch {
            if (-not [bool]$Server.state['stop_requested']) {
                $errorText = $_.Exception.Message
            }
        }
    } catch {
        $errorText = $_.Exception.Message
    } finally {
        try { $Server.powershell.Dispose() } catch {}
    }
    $evidence = $null
    if (Test-Path -LiteralPath $Server.evidence_path -PathType Leaf) {
        try {
            $evidence = Get-Content -LiteralPath $Server.evidence_path -Raw |
                ConvertFrom-Json -ErrorAction Stop
        } catch {
            if (-not $errorText) { $errorText = $_.Exception.Message }
        }
    }
    return [pscustomobject][ordered]@{
        stopped = $Server.async.IsCompleted -or
            [string]$Server.state['phase'] -in @('stopped', 'error')
        error = $errorText
        evidence = $evidence
    }
}

function Invoke-I03PeerRole {
    if (-not (Test-I03Administrator)) {
        throw 'Peer role requires an elevated PowerShell for complete PID/socket evidence'
    }
    if (-not $RunNonce) {
        throw 'Peer role requires the coordinator-issued RunNonce'
    }
    $nonce = $RunNonce.ToLowerInvariant()
    $repositoryRoot = Get-LabFullPath -Path (
        Join-Path $PSScriptRoot '..\..'
    )
    $outputPath = Assert-I03PrivateRoot -Path $OutputRoot `
        -Label 'OUTPUT' -RepositoryRoot $repositoryRoot `
        -CandidatePackageRoot $candidate.package_path
    $coordinationRootPath = Assert-I03PrivateRoot `
        -Path $CoordinationRoot -Label 'COORDINATION' `
        -RepositoryRoot $repositoryRoot `
        -CandidatePackageRoot $candidate.package_path
    if ((Test-I03PathContainedBy -Path $outputPath `
            -Root $coordinationRootPath) -or
        (Test-I03PathContainedBy -Path $coordinationRootPath `
            -Root $outputPath)) {
        throw 'I03_PRIVATE_ROOT::OUTPUT_COORDINATION_OVERLAP'
    }
    $packageRootWithSeparator =
        (Get-LabFullPath -Path $candidate.package_path).TrimEnd('\') + '\'
    if (($outputPath.TrimEnd('\') + '\').StartsWith(
        $packageRootWithSeparator,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'Peer OutputRoot must not be inside the candidate package'
    }
    if (Test-Path -LiteralPath $outputPath) {
        if (@(Get-ChildItem -LiteralPath $outputPath -Force).Count -ne 0) {
            throw "Peer OutputRoot must be absent or empty: $outputPath"
        }
    }
    $output = New-LabDirectory -Path $outputPath
    $evidence = New-LabDirectory -Path (Join-Path $output 'private')
    $publicEvidence = New-LabDirectory -Path (Join-Path $output 'evidence')
    $nodes = New-LabDirectory -Path (Join-Path $output 'nodes')
    $coordination = Get-LabFullPath -Path (Join-Path `
        $coordinationRootPath "v91-i03-$nonce")
    if (($coordination.TrimEnd('\') + '\').StartsWith(
        $packageRootWithSeparator,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'Peer CoordinationRoot must not be inside the candidate package'
    }
    if (-not (Test-Path -LiteralPath $coordination -PathType Container)) {
        throw "Peer requires the coordinator run directory: $coordination"
    }
    $entries = @(
        Get-ChildItem -LiteralPath $coordination -Force -ErrorAction Stop
    )
    if ($entries.Count -ne 1 -or $entries[0].Name -ne 'run.json') {
        throw 'Peer coordination directory is not pristine (expected only run.json)'
    }
    $runPath = Join-Path $coordination 'run.json'
    $peerPackagePreflight =
        Get-I03PackageIdentity -PackagePath $candidate.package_path
    $peerZipPreflight = Get-I03ZipPackageBinding `
        -ZipPath $candidateZip -ExpectedZipSha256 $expectedZipHash `
        -PackageIdentity $peerPackagePreflight
    $manifest = Get-Content -LiteralPath $runPath -Raw |
        ConvertFrom-Json -ErrorAction Stop
    if ([string]$manifest.schema -ne 'ese.v91.i03-run/v1' -or
        [string]$manifest.case_id -ne $caseId -or
        [string]$manifest.run_nonce -ne $nonce -or
        [string]$manifest.candidate.commit -ne $candidate.commit -or
        [string]$manifest.candidate.emule_sha256 -ne $expectedHash -or
        [string]$manifest.candidate.ese_server_sha256 -ne
            $candidate.ese_server_sha256 -or
        [string]$manifest.candidate.build_info_sha256 -ne
            $candidate.build_info_sha256 -or
        [string]$manifest.candidate.zip_sha256 -ne
            $peerZipPreflight.zip_sha256 -or
        [Int64]$manifest.candidate.zip_bytes -ne
            [Int64]$peerZipPreflight.zip_bytes -or
        [string]$manifest.candidate.package_manifest_sha256 -ne
            $peerPackagePreflight.manifest_sha256 -or
        [int]$manifest.candidate.package_file_count -ne
            [int]$peerPackagePreflight.file_count -or
        [Int64]$manifest.candidate.package_total_bytes -ne
            [Int64]$peerPackagePreflight.total_bytes -or
        -not [bool]$manifest.lab_account.
            disposable_account_acknowledged -or
        [string]$manifest.lab_account.
            coordinator_user_sid_sha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]$manifest.peer.public_ipv4 -ne $peerV4Text -or
        [string]$manifest.peer.local_ipv4 -ne $peerLocalV4Text -or
        [string]$manifest.peer.public_ipv6 -ne $peerV6Text -or
        [int]$manifest.peer.tcp_port -ne $PeerTcpPort -or
        [int]$manifest.peer.udp_port -ne $PeerUdpPort -or
        [int]$manifest.peer.web_port -ne $PeerWebPort -or
        [Int64]$manifest.file_size_bytes -ne $FileSizeBytes) {
        throw 'Peer arguments/package do not exactly match run.json'
    }

    $readyPath = Join-Path $coordination 'peer-ready.json'
    $baselineCommandPath = Join-Path $coordination 'baseline.json'
    $baselineAckPath = Join-Path $coordination 'peer-baseline-ack.json'
    $stopPath = Join-Path $coordination 'stop.json'
    $peerResultPath = Join-Path $coordination 'peer-result.json'
    $source = $null
    $sourceExpectedIdentity = $null
    $sourceNode = ''
    $sourceExe = ''
    $sourceIdentity = ''
    $currentSourcePid = 0
    $fixture = $null
    $shared = $null
    $peerTopology = $null
    $runtimeFailure = $null
    $cleanupFailures = [System.Collections.Generic.List[string]]::new()
    $barriersCompleted = 0
    $peerStopped = $false
    $candidateUnchanged = $false
    $nodeUnchanged = $false
    $peerPreferencesOracle = $null
    $peerNodeInitialBinding = $null
    $peerNodeTerminalBinding = $null
    $packageIdentityBefore = $null
    $packageIdentityAfter = $null
    $packageManifestUnchanged = $false
    $packageZipBindingBefore = $null
    $packageZipBindingAfter = $null
    $packageZipBindingUnchanged = $false
    $mutationBaseline = $null
    $mutationCleanup = $null
    $sourcePassword = 'v91-i03-peer'
    $peerFailureRecords = [System.Collections.Generic.List[object]]::new()
    $peerFailureSourceFiles = [System.Collections.Generic.List[object]]::new()
    $peerOwnedProcessIds =
        [System.Collections.Generic.HashSet[int]]::new()
    $peerCurrentPolicy = 'none'
    $peerFailurePhase = 'preflight'
    $peerFixtureCertified = $false

    function Add-I03PeerFailure {
        param(
            [Parameter(Mandatory = $true)][string]$Status,
            [Parameter(Mandatory = $true)][string]$Code,
            [Parameter(Mandatory = $true)][string]$Reason,
            [object[]]$Proofs = @()
        )
        if ($null -eq $packageIdentityBefore) { return $null }
        $categories = [ordered]@{
            CANDIDATE_EXITED = 'PRODUCT_RUNTIME'
            API_UNAVAILABLE = 'PRODUCT_LIVENESS'
            API_CONTRACT = 'PRODUCT_CONTRACT'
            PEER_IDENTITY_CHANGED = 'PRODUCT_IDENTITY'
            WRONG_OR_NONPHYSICAL_SOCKET = 'PRODUCT_ATTRIBUTION'
            PACKAGE_BINDING = 'LAB_PACKAGE'
            TOPOLOGY = 'LAB_TOPOLOGY'
            CONTROL_TIMEOUT = 'LAB_CONTROL'
            COORDINATION_SCHEMA = 'LAB_CONTROL'
            COLLECTOR_UNAVAILABLE = 'LAB_COLLECTOR'
            COLLECTOR_AMBIGUOUS = 'LAB_COLLECTOR'
            EXTERNAL_CONTAMINATION = 'LAB_CONTAMINATION'
            EVIDENCE_INCOMPLETE = 'LAB_EVIDENCE'
            CLEANUP_INCOMPLETE = 'LAB_CLEANUP'
            HARNESS_EXCEPTION = 'LAB_HARNESS'
        }
        if (-not $categories.Contains($Code)) {
            throw 'I03_FAILURE_PROTOCOL::UNKNOWN_PEER_CODE'
        }
        $record = New-I03FailureRecord -CaseId $caseId `
            -RunNonce $nonce -Role 'Peer' -Policy $peerCurrentPolicy `
            -Phase $peerFailurePhase -Status $Status `
            -Category ([string]$categories[$Code]) -Code $Code `
            -Message $Reason -CandidateCommit $candidate.commit `
            -CandidateEmuleSha256 $expectedHash `
            -CandidateZipSha256 $expectedZipHash `
            -PackageManifestSha256 $packageIdentityBefore.manifest_sha256 `
            -FixtureCertified $peerFixtureCertified -Proofs $Proofs
        $peerFailureRecords.Add($record)
        return $record
    }

    function Stop-I03PeerLab {
        param(
            [Parameter(Mandatory = $true)][string]$Code,
            [Parameter(Mandatory = $true)][string]$Reason
        )
        $null = Add-I03PeerFailure -Status 'LAB_BLOCKED' `
            -Code $Code -Reason $Reason
        throw "I03_LAB_BLOCKED::$Code"
    }

    function Assert-I03PeerReservedPortsFree {
        try {
            Wait-I03PortSetFree -Ports $allPorts
        } catch {
            if ([string]$_.Exception.Message -match
                '^I03_COLLECTOR::') {
                Stop-I03PeerLab -Code 'COLLECTOR_UNAVAILABLE' `
                    -Reason 'Peer reserved-port collector failed'
            }
            Stop-I03PeerLab -Code 'EXTERNAL_CONTAMINATION' `
                -Reason 'A reserved candidate port was not free on peer host'
        }
    }

    function Stop-I03PeerProduct {
        param(
            [Parameter(Mandatory = $true)][string]$Code,
            [Parameter(Mandatory = $true)][string]$Reason,
            [Parameter(Mandatory = $true)][AllowNull()][object]$SourceEvidence
        )
        if (-not $peerFixtureCertified -or
            $peerCurrentPolicy -notin @('auto', 'preferred')) {
            Stop-I03PeerLab -Code 'EVIDENCE_INCOMPLETE' `
                -Reason 'Peer product classification preceded certification'
        }
        $sourceName = 'peer-failure-source-{0:D3}.json' -f (
            $peerFailureSourceFiles.Count + 1
        )
        $sourcePath = Join-Path $coordination $sourceName
        try {
            Write-LabJson -Value ([ordered]@{
                schema = 'ese.v91.i03-failure-source/v1'
                case_id = $caseId
                run_nonce = $nonce
                role = 'Peer'
                policy = $peerCurrentPolicy
                phase = $peerFailurePhase
                code = $Code
                evidence = $SourceEvidence
            }) -Path $sourcePath | Out-Null
            $sourceHash = Get-LabSha256 -Path $sourcePath
            $verified = Get-Content -LiteralPath $sourcePath -Raw `
                -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if ([string]$verified.schema -cne
                    'ese.v91.i03-failure-source/v1' -or
                [string]$verified.role -cne 'Peer' -or
                [string]$verified.policy -cne $peerCurrentPolicy -or
                [string]$verified.phase -cne $peerFailurePhase -or
                [string]$verified.code -cne $Code -or
                (Get-LabSha256 -Path $sourcePath) -cne $sourceHash) {
                throw 'I03_FAILURE_SOURCE::VERIFY_FAILED'
            }
            $peerFailureSourceFiles.Add([pscustomobject][ordered]@{
                file_name = $sourceName
                sha256 = $sourceHash
                bytes = [Int64](Get-Item -LiteralPath $sourcePath).Length
            })
        } catch {
            Stop-I03PeerLab -Code 'EVIDENCE_INCOMPLETE' `
                -Reason 'Peer failure source persistence failed'
        }
        $proof = New-I03ProofProjection -Kind ($Code.ToLowerInvariant()) `
            -CaseId $caseId -RunNonce $nonce -Role 'Peer' `
            -Policy $peerCurrentPolicy -Phase $peerFailurePhase `
            -SourceEvidenceSha256 $sourceHash
        $null = Add-I03PeerFailure -Status 'PRODUCT_INVARIANT' `
            -Code $Code -Reason $Reason -Proofs @($proof)
        throw "I03_PRODUCT_INVARIANT::$Code"
    }

    function Start-I03PeerSource {
        $process = $null
        $processIdentity = $null
        try {
            # Do not use --headless here. The candidate intentionally
            # regenerates its userhash on every headless startup; that would
            # turn each controlled restart into a different peer.
            $process = Start-Process -FilePath $sourceExe `
                -ArgumentList @(
                    '--portable', '--ignoreinstances',
                    "--metrics-port=$PeerWebPort",
                    "--tcp-port=$PeerTcpPort",
                    "--udp-port=$PeerUdpPort"
                ) -WorkingDirectory $sourceNode -PassThru -WindowStyle Hidden
            $processIdentity = Get-I03ProcessIdentity -Process $process
            [void]$peerOwnedProcessIds.Add([int]$process.Id)
            $listener = Wait-I03Listener -Port $PeerTcpPort `
                -Process $process -RequireDualStack
            $api = Wait-I03Api -Port $PeerWebPort -Process $process
            if (-not (Test-I03ApiIsolation -Data $api)) {
                throw 'Peer API shows NetLab, Kad or server activity'
            }
            if ((Get-LabSha256 -Path $process.Path) -ne $expectedHash) {
                throw 'Started peer process is not the exact candidate'
            }
            return [pscustomobject][ordered]@{
                process = $process
                process_identity = $processIdentity
                listener = $listener
                api = $api
            }
        } catch {
            if ($null -ne $process) {
                $stopped = Stop-I03OwnedProcess -Process $process `
                    -ExpectedPath $sourceExe `
                    -ExpectedIdentity $processIdentity
                if (-not $stopped.stopped -or
                    -not $stopped.collector_ok -or
                    $stopped.unexpected_descendant_count -ne 0) {
                    $cleanupFailures.Add(
                        "partially started peer process $($process.Id) remains"
                    )
                }
            }
            throw
        }
    }

    try {
        $packageIdentityBefore =
            Get-I03PackageIdentity -PackagePath $candidate.package_path
        $packageZipBindingBefore = Get-I03ZipPackageBinding `
            -ZipPath $candidateZip -ExpectedZipSha256 $expectedZipHash `
            -PackageIdentity $packageIdentityBefore
        Write-LabJson -Value $packageIdentityBefore -Path (
            Join-Path $evidence 'package-manifest-before.json'
        ) | Out-Null
        Write-LabJson -Value $packageZipBindingBefore -Path (
            Join-Path $evidence 'package-zip-binding-before.json'
        ) | Out-Null
        $preexistingProcesses = Get-I03EmuleProcessCensus
        Write-LabJson -Value $preexistingProcesses -Path (
            Join-Path $evidence 'preexisting-emule-process-census.json'
        ) | Out-Null
        if (-not [bool]$preexistingProcesses.collector_ok) {
            Stop-I03PeerLab -Code 'COLLECTOR_UNAVAILABLE' `
                -Reason 'Preexisting eMule process collector failed'
        }
        if ([int]$preexistingProcesses.process_count -ne 0) {
            Stop-I03PeerLab -Code 'EXTERNAL_CONTAMINATION' `
                -Reason 'Preexisting eMule process detected on peer host'
        }
        Test-I03PortSetFree -Ports @(
            $PeerTcpPort, $PeerUdpPort, $PeerWebPort
        )
        $localV4 = Get-I03AssignedAddress -Address $peerLocalV4Text `
            -Family ([Net.Sockets.AddressFamily]::InterNetwork) `
            -Context 'peer-local-ipv4'
        $localV6 = Get-I03AssignedAddress -Address $peerV6Text `
            -Family ([Net.Sockets.AddressFamily]::InterNetworkV6) `
            -Context 'peer-public-ipv6'
        if ([int]$localV4.interface_index -ne [int]$localV6.interface_index) {
            throw 'Peer local IPv4 and public IPv6 are not on the same adapter'
        }
        if ([string]$localV6.address_class -cne 'global-native-v6') {
            throw 'Peer assigned IPv6 is not strict native global unicast'
        }
        if (-not $localV4.adapter.physical_nonvirtual -or
            -not $localV6.adapter.physical_nonvirtual) {
            throw 'Peer dual-stack addresses are not on an Up physical non-virtual adapter'
        }
        $peerMachineIdentity = Get-I03MachineIdentityEvidence
        if (-not [bool]$peerMachineIdentity.physical_host_claim -or
            [bool]$peerMachineIdentity.virtual_signature_detected) {
            Stop-I03PeerLab -Code 'TOPOLOGY' `
                -Reason 'Peer Win32_ComputerSystem identifies a virtual host'
        }
        $peerTopology = [ordered]@{
            machine_id_sha256 =
                [string]$peerMachineIdentity.machine_id_sha256
            machine_identity = $peerMachineIdentity
            computer_name_sha256 = Get-LabStringSha256 `
                -Value $env:COMPUTERNAME
            local_ipv4 = $localV4
            public_ipv6 = $localV6
            same_adapter = [int]$localV4.interface_index -eq
                [int]$localV6.interface_index
            public_ipv4_endpoint = $peerV4Text
            public_ipv4_may_be_nat_mapped = $peerV4Text -ne $peerLocalV4Text
        }

        $offset = $PeerTcpPort - 4662
        if (($PeerUdpPort - 4672) -ne $offset -or
            ($PeerWebPort - 4711) -ne $offset) {
            throw 'Peer TCP/UDP/Web ports must share the standard offset'
        }
        $sourceNode = Join-Path $nodes 'v91-i03-peer-a'
        $sourceExe = Join-Path $sourceNode 'emule.exe'
        $peerAutostartValueHash = Get-LabStringSha256 -Value (
            (Get-LabFullPath -Path $sourceExe) + ' -AutoStart'
        )
        $mutationBaseline = Get-I03MutationBaseline `
            -AllowedAutostartValueSha256 @($peerAutostartValueHash)
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i03-transaction-active/v1'
            case_id = $caseId
            run_nonce = $nonce
            role = 'Peer'
            candidate_commit = $candidate.commit
            candidate_emule_sha256 = $expectedHash
            candidate_zip_sha256 = $expectedZipHash
            package_manifest_sha256 =
                $packageIdentityBefore.manifest_sha256
            lab_user_sid_sha256 = $currentLabSidHash
            forbidden_state_digests =
                $mutationBaseline.forbidden_state
            autostart_state_sha256 =
                $mutationBaseline.autostart.state_sha256
            run_key_state_sha256 =
                $mutationBaseline.run_key.state_sha256
            ed2k_association_state_sha256 =
                $mutationBaseline.ed2k_association.state_sha256
        }) -Path (Join-Path $evidence 'transaction-active.json') | Out-Null
        $peerPreferencesOracle = New-I03PreparedPreferencesOracle `
            -PackagePath $candidate.package_path `
            -PackageIdentity $packageIdentityBefore `
            -OracleRoot (Join-Path $evidence `
                'prepared-preferences-oracle-peer') `
            -NodeRole A -RunId 'v91-i03-peer' -PortOffset $offset
        Write-LabJson -Value $peerPreferencesOracle -Path (
            Join-Path $evidence 'prepared-preferences-oracle-peer.json'
        ) | Out-Null
        if (-not [bool]$peerPreferencesOracle.collector_ok) {
            Stop-I03PeerLab -Code 'COLLECTOR_UNAVAILABLE' `
                -Reason 'Peer deterministic preferences oracle failed'
        }
        if (-not [bool]$peerPreferencesOracle.source_bound) {
            Stop-I03PeerLab -Code 'PACKAGE_BINDING' `
                -Reason 'Peer source preferences did not match frozen manifest'
        }
        & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole A `
            -SourcePackage $candidate.package_path -OutputRoot $nodes `
            -RunId 'v91-i03-peer' -PortOffset $offset
        $peerNodeInitialBinding = Test-I03PreparedNodeBinding `
            -NodePath $sourceNode -PackageIdentity $packageIdentityBefore `
            -Phase Initial `
            -ExpectedPreparedPreferencesSha256 `
                $peerPreferencesOracle.expected_prepared_preferences_sha256 `
            -ExpectedPreparedPreferencesBytes `
                $peerPreferencesOracle.expected_prepared_preferences_bytes
        Write-LabJson -Value $peerNodeInitialBinding -Path (
            Join-Path $evidence 'prepared-node-binding-initial.json'
        ) | Out-Null
        if (-not [bool]$peerNodeInitialBinding.collector_ok) {
            Stop-I03PeerLab -Code 'COLLECTOR_UNAVAILABLE' `
                -Reason 'Peer prepared-node binding collector failed'
        }
        if (-not [bool]$peerNodeInitialBinding.bound) {
            Stop-I03PeerLab -Code 'PACKAGE_BINDING' `
                -Reason 'Peer prepared node did not match frozen package manifest'
        }
        $incoming = New-LabDirectory `
            -Path (Join-Path $sourceNode 'I03Incoming')
        $temp = New-LabDirectory -Path (Join-Path $sourceNode 'I03Temp')
        $peerIsolation = Set-I03IsolatedPreferences -NodePath $sourceNode `
            -IPv6Mode 1 -IPv6BindAddress '::' `
            -WebPort $PeerWebPort -Password $sourcePassword `
            -IncomingPath $incoming -TempPath $temp `
            -MaxUploadKiBps $peerUploadCapKiBps

        # One clean normal-mode initialization makes preferences.dat and its
        # userhash durable before the campaign. A graceful stop is mandatory.
        Assert-I03PeerReservedPortsFree
        $initialized = Start-I03PeerSource
        $source = $initialized.process
        $sourceExpectedIdentity = $initialized.process_identity
        $initStop = Stop-I03OwnedProcess -Process $source `
            -ExpectedPath $sourceExe `
            -ExpectedIdentity $sourceExpectedIdentity -RequireGraceful
        if (-not $initStop.stopped -or -not $initStop.graceful -or
            -not $initStop.collector_ok -or
            $initStop.unexpected_descendant_count -ne 0) {
            throw 'Peer identity initialization did not stop gracefully'
        }
        $source = $null
        $sourceIdentity = Get-I03UserHashSha256 -NodePath $sourceNode
        if ($sourceIdentity -notmatch '^[0-9a-f]{64}$' -or
            -not $peerIsolation.preferences_dat_absent_before_start -or
            -not $peerIsolation.cryptkey_dat_absent_before_start -or
            [int]$peerIsolation.max_upload_kib_per_second -ne
                $peerUploadCapKiBps -or
            -not [bool]$peerIsolation.dynamic_upload_disabled) {
            throw 'Peer fresh isolated identity bootstrap could not be proved'
        }

        # UploadDiskIOThread deliberately skips compression for .zip. The
        # payload need not be a valid archive; the extension guarantees the
        # wire carries the logical bytes instead of collapsing zero ranges.
        $fileName = "v91-i03-$nonce.zip"
        $filePath = Join-Path $incoming $fileName
        $stream = [IO.File]::Open(
            $filePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try {
            $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
            try {
                $buffer = New-Object byte[] (1MB)
                $rng.GetBytes($buffer)
                $stream.Write($buffer, 0, $buffer.Length)
            } finally {
                $rng.Dispose()
            }
            $stream.SetLength($FileSizeBytes)
            $stream.Flush($true)
        } finally {
            $stream.Dispose()
        }
        $fixture = [ordered]@{
            name = $fileName
            bytes = $FileSizeBytes
            sha256 = Get-LabSha256 -Path $filePath
            generation = 'nonce filename plus materialized CSPRNG first MiB'
            upload_compression_disabled_by_extension = $true
            peer_max_upload_kib_per_second =
                $peerUploadCapKiBps
        }

        Assert-I03PeerReservedPortsFree
        $started = Start-I03PeerSource
        $source = $started.process
        $sourceExpectedIdentity = $started.process_identity
        $currentSourcePid = $source.Id
        if ((Get-I03UserHashSha256 -NodePath $sourceNode) -ne
            $sourceIdentity) {
            throw 'Peer userhash changed before the campaign began'
        }
        $session = Get-I03ClassicSession -Port $PeerWebPort `
            -Password $sourcePassword
        $shared = Get-I03SharedLink -Port $PeerWebPort -Session $session `
            -FileName $fileName -FileBytes $FileSizeBytes
        if ([string]$shared.link -match '(?i)\|sources,' -or
            [string]$shared.link -match [regex]::Escape($peerV6Text)) {
            throw 'Base fixture link unexpectedly contains a source endpoint'
        }

        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i03-peer-ready/v1'
            case_id = $caseId
            run_nonce = $nonce
            ready_at_utc = Get-LabUtcTimestamp
            lab_account = [ordered]@{
                disposable_account_acknowledged =
                    [bool]$DisposableLabAccountAcknowledged
                current_user_sid_sha256 = $currentLabSidHash
                expected_sid_binding_exact =
                    $currentLabSidHash -ceq $expectedLabSidHash
            }
            candidate = [ordered]@{
                commit = $candidate.commit
                emule_sha256 = $expectedHash
                ese_server_sha256 = $candidate.ese_server_sha256
                build_info_sha256 = $candidate.build_info_sha256
                extracted_package_manifest_sha256 =
                    $packageIdentityBefore.manifest_sha256
                extracted_package_file_count =
                    $packageIdentityBefore.file_count
                extracted_package_total_bytes =
                    $packageIdentityBefore.total_bytes
                zip_sha256 = $packageZipBindingBefore.zip_sha256
                zip_bytes = $packageZipBindingBefore.zip_bytes
            }
            peer = $peerTopology
            endpoint = [ordered]@{
                public_ipv4 = $peerV4Text
                local_ipv4 = $peerLocalV4Text
                public_ipv6 = $peerV6Text
                tcp_port = $PeerTcpPort
                dual_stack_listener = [bool]$started.listener.dual_stack
                ipv6_bind_preference = '::'
                expected_public_ipv6 = $peerV6Text
            }
            process = [ordered]@{
                id = $source.Id
                executable_sha256 = Get-LabSha256 -Path $source.Path
                headless = $false
                stable_userhash_sha256 = $sourceIdentity
                identity_profile = $peerIsolation
            }
            fixture = $fixture
            ed2k = [ordered]@{
                base_link = $shared.link
                hash = $shared.ed2k_hash
                source_extensions_present = $false
            }
            isolation = [ordered]@{
                dns_used = $false
                kad_enabled = $false
                server_enabled = $false
                netlab_enabled = $false
                web_allowed_ips = '127.0.0.1'
                firewall_modified = $false
            }
        }) -Path $readyPath | Out-Null

        $baselineControl = Wait-I03JsonFile -Path $baselineCommandPath `
            -StopPath $stopPath -TimeoutSeconds $CaseTimeoutSeconds
        if ($null -eq $baselineControl) {
            throw 'Coordinator did not issue baseline or stop'
        }
        if ($baselineControl.kind -eq 'stop') {
            throw 'Coordinator stopped before baseline completed'
        }
        $baselineClockT1 = [DateTime]::UtcNow
        $baseline = $baselineControl.value
        if ([string]$baseline.schema -ne
                'ese.v91.i03-baseline-command/v1' -or
            [string]$baseline.case_id -ne $caseId -or
            [string]$baseline.run_nonce -ne $nonce -or
            [string]$baseline.candidate_commit -ne $candidate.commit -or
            [string]$baseline.candidate_emule_sha256 -ne $expectedHash -or
            [int]$baseline.expected_source_process_id -ne $source.Id -or
            [string]$baseline.clock_t0_utc -notmatch 'Z$') {
            throw 'Peer received an invalid baseline command'
        }
        $baselineDeadline = [DateTime]::UtcNow.AddSeconds(10)
        $baselineInbound = @()
        $baselineInboundV4 = @()
        $baselineInboundV6 = @()
        $dualMarker = $null
        do {
            $baselineInbound = @(
                Get-I03PeerInboundConnectionSnapshot `
                    -ProcessId $source.Id -LocalPort $PeerTcpPort
            )
            $baselineInboundV4 = @($baselineInbound | Where-Object {
                $_.local_address -eq $peerLocalV4Text
            })
            $baselineInboundV6 = @($baselineInbound | Where-Object {
                $_.local_address -eq $peerV6Text
            })
            $dualMarker = Get-I03PeerDualStackMarker -NodePath $sourceNode `
                -SnapshotRoot $evidence
            if (-not [bool]$dualMarker.collector_ok) {
                throw "I03_COLLECTOR::$($dualMarker.collector_error_code)"
            }
            if ($baselineInbound.Count -eq 2 -and
                $baselineInboundV4.Count -eq 1 -and
                $baselineInboundV6.Count -eq 1 -and
                $dualMarker.dualstack_capability_armed) {
                break
            }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $baselineDeadline)
        $dualMarker = Get-I03PeerDualStackMarker -NodePath $sourceNode `
            -SnapshotRoot $evidence -PersistSnapshots
        if (-not [bool]$dualMarker.collector_ok) {
            throw "I03_COLLECTOR::$($dualMarker.collector_error_code)"
        }
        $peerApi = Get-I03ApiProbe -Port $PeerWebPort
        if ($baselineInbound.Count -ne 2 -or
            $baselineInboundV4.Count -ne 1 -or
            $baselineInboundV6.Count -ne 1 -or
            -not $dualMarker.dualstack_capability_armed -or
            -not $peerApi.available -or -not $peerApi.isolation_valid) {
            throw 'Peer could not prove exact live IPv4+IPv6 baseline sockets and DUALSTACK arming'
        }
        $baselineClockT2 = [DateTime]::UtcNow
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i03-peer-baseline-ack/v1'
            case_id = $caseId
            run_nonce = $nonce
            candidate_commit = $candidate.commit
            candidate_emule_sha256 = $expectedHash
            source_process_id = $source.Id
            source_process_emule_sha256 = Get-LabSha256 -Path $source.Path
            source_userhash_sha256 = $sourceIdentity
            clock = [ordered]@{
                t0_coordinator_send_utc =
                    [string]$baseline.clock_t0_utc
                t1_peer_receive_utc = $baselineClockT1.ToString('o')
                t2_peer_send_utc = $baselineClockT2.ToString('o')
            }
            inbound_connections = $baselineInbound
            dualstack_marker = $dualMarker
            api = $peerApi
        }) -Path $baselineAckPath | Out-Null

        foreach ($policy in @(
            [pscustomobject]@{ name = 'auto'; mode = 1; family = 'IPv4' },
            [pscustomobject]@{ name = 'preferred'; mode = 2; family = 'IPv6' }
        )) {
            $peerCurrentPolicy = [string]$policy.name
            $peerFailurePhase = 'dualstack_rearm'
            $peerFixtureCertified = $false
            $rearmPath = Join-Path $coordination `
                "$($policy.name)-rearm.json"
            $rearmAckPath = Join-Path $coordination `
                "peer-$($policy.name)-rearm-ack.json"
            $prewarmPath = Join-Path $coordination `
                "$($policy.name)-prewarm.json"
            $prewarmAckPath = Join-Path $coordination `
                "peer-$($policy.name)-prewarm-ack.json"
            $restartPath = Join-Path $coordination `
                "$($policy.name)-restart.json"
            $restartedPath = Join-Path $coordination `
                "peer-$($policy.name)-restarted.json"
            $donePath = Join-Path $coordination "$($policy.name)-done.json"
            $completePath = Join-Path $coordination `
                "peer-$($policy.name)-complete.json"

            # g_uForkCapsRuntime is process-local and is reset by every peer
            # restart. Require a nonce-scoped native-v6 socket on the CURRENT
            # source PID and a fresh log-marker delta before each prewarm.
            $markerBefore = Get-I03PeerDualStackMarker `
                -NodePath $sourceNode -SnapshotRoot $evidence `
                -PersistSnapshots
            if (-not [bool]$markerBefore.collector_ok) {
                throw "I03_COLLECTOR::$($markerBefore.collector_error_code)"
            }
            $rearmControl = Wait-I03JsonFile -Path $rearmPath `
                -StopPath $stopPath -TimeoutSeconds $CaseTimeoutSeconds
            if ($null -eq $rearmControl -or
                $rearmControl.kind -eq 'stop') {
                throw "Coordinator stopped before $($policy.name) DUALSTACK rearm"
            }
            $rearm = $rearmControl.value
            if ([string]$rearm.schema -ne
                    'ese.v91.i03-rearm-command/v1' -or
                [string]$rearm.case_id -ne $caseId -or
                [string]$rearm.run_nonce -ne $nonce -or
                [string]$rearm.policy -ne $policy.name -or
                [int]$rearm.ipv6_mode -ne $policy.mode -or
                [string]$rearm.candidate_commit -ne $candidate.commit -or
                [string]$rearm.candidate_emule_sha256 -ne $expectedHash -or
                [int]$rearm.expected_source_process_id -ne $source.Id -or
                [string]$rearm.coordinator_local_ipv6 -notmatch ':' -or
                [int]$rearm.coordinator_local_port -le 0) {
                throw "Invalid $($policy.name) DUALSTACK rearm command"
            }
            $peerFixtureCertified = $true
            $peerFailurePhase = 'dualstack_rearm'
            $rearmInbound = @()
            $markerAfter = $markerBefore
            $inboundDelta = 0
            $acceptedDelta = 0
            $rearmDeadline = [DateTime]::UtcNow.AddSeconds(10)
            do {
                $rearmInbound = @(
                    Get-I03PeerInboundConnectionSnapshot `
                        -ProcessId $source.Id -LocalPort $PeerTcpPort
                )
                $markerAfter =
                    Get-I03PeerDualStackMarker -NodePath $sourceNode `
                        -SnapshotRoot $evidence
                if (-not [bool]$markerAfter.collector_ok) {
                    throw "I03_COLLECTOR::$($markerAfter.collector_error_code)"
                }
                $inboundDelta =
                    [int]$markerAfter.inbound_reachability_markers -
                    [int]$markerBefore.inbound_reachability_markers
                $acceptedDelta =
                    [int]$markerAfter.accepted_native_ipv6_markers -
                    [int]$markerBefore.accepted_native_ipv6_markers
                if ($rearmInbound.Count -eq 1 -and
                    $inboundDelta -ge 1 -and $acceptedDelta -ge 1) {
                    break
                }
                Start-Sleep -Milliseconds 100
            } while ([DateTime]::UtcNow -lt $rearmDeadline)
            $markerAfter = Get-I03PeerDualStackMarker `
                -NodePath $sourceNode -SnapshotRoot $evidence `
                -PersistSnapshots
            if (-not [bool]$markerAfter.collector_ok) {
                throw "I03_COLLECTOR::$($markerAfter.collector_error_code)"
            }
            $inboundDelta =
                [int]$markerAfter.inbound_reachability_markers -
                [int]$markerBefore.inbound_reachability_markers
            $acceptedDelta =
                [int]$markerAfter.accepted_native_ipv6_markers -
                [int]$markerBefore.accepted_native_ipv6_markers
            if ($rearmInbound.Count -ne 1 -or
                $rearmInbound[0].local_address -ne $peerV6Text -or
                $rearmInbound[0].remote_address -ne
                    (Get-I03NormalizedIp -Address `
                        ([string]$rearm.coordinator_local_ipv6)) -or
                $rearmInbound[0].remote_port -ne
                    [int]$rearm.coordinator_local_port -or
                $inboundDelta -ne 1 -or $acceptedDelta -ne 1 -or
                (Get-I03UserHashSha256 -NodePath $sourceNode) -ne
                    $sourceIdentity) {
                $rearmCode = if (
                    (Get-I03UserHashSha256 -NodePath $sourceNode) -ne
                        $sourceIdentity
                ) { 'PEER_IDENTITY_CHANGED' } else {
                    'WRONG_OR_NONPHYSICAL_SOCKET'
                }
                Stop-I03PeerProduct -Code $rearmCode `
                    -SourceEvidence ([ordered]@{
                        inbound_connections = $rearmInbound
                        marker_before = $markerBefore
                        marker_after = $markerAfter
                        inbound_delta = $inboundDelta
                        accepted_delta = $acceptedDelta
                    }) -Reason 'Peer current-PID dual-stack rearm invariant failed'
            }
            Write-LabJson -Value ([ordered]@{
                schema = 'ese.v91.i03-peer-rearm-ack/v1'
                case_id = $caseId
                run_nonce = $nonce
                policy = $policy.name
                ipv6_mode = $policy.mode
                candidate_commit = $candidate.commit
                candidate_emule_sha256 = $expectedHash
                source_process_id = $source.Id
                source_process_emule_sha256 =
                    Get-LabSha256 -Path $source.Path
                source_userhash_sha256 = $sourceIdentity
                inbound_connection = $rearmInbound[0]
                marker_before = $markerBefore
                marker_after = $markerAfter
                inbound_marker_delta = $inboundDelta
                accepted_marker_delta = $acceptedDelta
                runtime_dualstack_rearmed = $true
            }) -Path $rearmAckPath | Out-Null

            $prewarmControl = Wait-I03JsonFile -Path $prewarmPath `
                -StopPath $stopPath -TimeoutSeconds $CaseTimeoutSeconds
            if ($null -eq $prewarmControl -or
                $prewarmControl.kind -eq 'stop') {
                throw "Coordinator stopped before $($policy.name) prewarm"
            }
            $prewarm = $prewarmControl.value
            $peerFailurePhase = 'ipv4_prewarm'
            if ([string]$prewarm.schema -ne
                    'ese.v91.i03-prewarm-command/v1' -or
                [string]$prewarm.case_id -ne $caseId -or
                [string]$prewarm.run_nonce -ne $nonce -or
                [string]$prewarm.policy -ne $policy.name -or
                [int]$prewarm.ipv6_mode -ne $policy.mode -or
                [string]$prewarm.expected_family -ne $policy.family -or
                [string]$prewarm.candidate_commit -ne $candidate.commit -or
                [string]$prewarm.candidate_emule_sha256 -ne $expectedHash -or
                [int]$prewarm.expected_source_process_id -ne $source.Id -or
                [int]$prewarm.client_process_id -le 0) {
                throw "Invalid $($policy.name) prewarm command"
            }
            $prewarmInbound = @(
                Get-I03PeerInboundConnectionSnapshot `
                    -ProcessId $source.Id -LocalPort $PeerTcpPort
            )
            $peerApi = Get-I03ApiProbe -Port $PeerWebPort
            if ($prewarmInbound.Count -ne 1 -or
                $prewarmInbound[0].local_address -ne $peerLocalV4Text) {
                Stop-I03PeerProduct `
                    -Code 'WRONG_OR_NONPHYSICAL_SOCKET' `
                    -SourceEvidence $prewarmInbound `
                    -Reason 'Peer IPv4 prewarm inbound tuple was not exact'
            }
            if (-not $peerApi.available) {
                Stop-I03PeerProduct -Code 'API_UNAVAILABLE' `
                    -SourceEvidence $peerApi `
                    -Reason 'Peer API unavailable during IPv4 prewarm'
            }
            if (-not $peerApi.isolation_valid) {
                Stop-I03PeerProduct -Code 'API_CONTRACT' `
                    -SourceEvidence $peerApi `
                    -Reason 'Peer API isolation changed during IPv4 prewarm'
            }
            if ((Get-I03UserHashSha256 -NodePath $sourceNode) -ne
                $sourceIdentity) {
                Stop-I03PeerProduct -Code 'PEER_IDENTITY_CHANGED' `
                    -SourceEvidence ([ordered]@{
                        process = $sourceExpectedIdentity
                        expected_identity_sha256 = $sourceIdentity
                    }) -Reason 'Peer identity changed during IPv4 prewarm'
            }
            Write-LabJson -Value ([ordered]@{
                schema = 'ese.v91.i03-peer-prewarm-ack/v1'
                case_id = $caseId
                run_nonce = $nonce
                policy = $policy.name
                ipv6_mode = $policy.mode
                candidate_commit = $candidate.commit
                candidate_emule_sha256 = $expectedHash
                source_process_id = $source.Id
                source_process_emule_sha256 = Get-LabSha256 -Path $source.Path
                source_userhash_sha256 = $sourceIdentity
                client_process_id_from_command = [int]$prewarm.client_process_id
                inbound_connection = $prewarmInbound[0]
                api = $peerApi
            }) -Path $prewarmAckPath | Out-Null
            $peerFixtureCertified = $true
            $peerFailurePhase = 'peer_restart'

            $restartControl = Wait-I03JsonFile -Path $restartPath `
                -StopPath $stopPath -TimeoutSeconds $CaseTimeoutSeconds
            if ($null -eq $restartControl -or
                $restartControl.kind -eq 'stop') {
                throw "Coordinator stopped before $($policy.name) restart"
            }
            $restart = $restartControl.value
            if ([string]$restart.schema -ne
                    'ese.v91.i03-restart-command/v1' -or
                [string]$restart.case_id -ne $caseId -or
                [string]$restart.run_nonce -ne $nonce -or
                [string]$restart.policy -ne $policy.name -or
                [string]$restart.action -ne 'restart-same-peer-source' -or
                [string]$restart.candidate_commit -ne $candidate.commit -or
                [string]$restart.candidate_emule_sha256 -ne $expectedHash -or
                [int]$restart.expected_old_process_id -ne $source.Id) {
                throw "Invalid $($policy.name) restart command"
            }
            $oldPid = $source.Id
            $watch = [Diagnostics.Stopwatch]::StartNew()
            $stopped = Stop-I03OwnedProcess -Process $source `
                -ExpectedPath $sourceExe `
                -ExpectedIdentity $sourceExpectedIdentity `
                -RequireGraceful
            if (-not $stopped.collector_ok) {
                Stop-I03PeerLab -Code 'COLLECTOR_UNAVAILABLE' `
                    -Reason 'Peer owned-process collector was unavailable'
            }
            if (-not $stopped.stopped -or -not $stopped.graceful -or
                $stopped.unexpected_descendant_count -ne 0) {
                Stop-I03PeerProduct -Code 'CANDIDATE_EXITED' `
                    -SourceEvidence $stopped `
                    -Reason 'Peer candidate did not stop under the bounded restart'
            }
            $source = $null
            if ((Get-I03UserHashSha256 -NodePath $sourceNode) -ne
                $sourceIdentity) {
                Stop-I03PeerProduct -Code 'PEER_IDENTITY_CHANGED' `
                    -SourceEvidence ([ordered]@{
                        old_process_id = $oldPid
                        expected_identity_sha256 = $sourceIdentity
                    }) -Reason 'Peer identity changed during bounded stop'
            }
            Start-Sleep -Milliseconds 250
            Assert-I03PeerReservedPortsFree
            try {
                $restarted = Start-I03PeerSource
            } catch {
                if ([string]$_.Exception.Message -match
                    '^I03_COLLECTOR::') {
                    Stop-I03PeerLab -Code 'COLLECTOR_UNAVAILABLE' `
                        -Reason 'Peer restart collector failed'
                }
                Stop-I03PeerProduct -Code 'CANDIDATE_EXITED' `
                    -SourceEvidence ([ordered]@{
                        old_process_id = $oldPid
                        phase = 'restart_startup'
                    }) -Reason 'Peer candidate failed to restart'
            }
            $source = $restarted.process
            $sourceExpectedIdentity = $restarted.process_identity
            $watch.Stop()
            $currentSourcePid = $source.Id
            if ($source.Id -eq $oldPid -or
                (Get-I03UserHashSha256 -NodePath $sourceNode) -ne
                    $sourceIdentity) {
                Stop-I03PeerProduct -Code 'PEER_IDENTITY_CHANGED' `
                    -SourceEvidence ([ordered]@{
                        old_process_id = $oldPid
                        new_process = $sourceExpectedIdentity
                        expected_identity_sha256 = $sourceIdentity
                    }) -Reason 'Peer restart changed identity or reused PID'
            }
            Write-LabJson -Value ([ordered]@{
                schema = 'ese.v91.i03-peer-restarted/v1'
                case_id = $caseId
                run_nonce = $nonce
                policy = $policy.name
                candidate_commit = $candidate.commit
                candidate_emule_sha256 = $expectedHash
                old_process_id = $oldPid
                process_id = $source.Id
                process_emule_sha256 = Get-LabSha256 -Path $source.Path
                source_userhash_sha256 = $sourceIdentity
                restart_elapsed_ms = [Int64]$watch.ElapsedMilliseconds
                dual_stack_listener = [bool]$restarted.listener.dual_stack
                api_isolation_valid = Test-I03ApiIsolation `
                    -Data $restarted.api
            }) -Path $restartedPath | Out-Null

            $doneControl = Wait-I03JsonFile -Path $donePath `
                -StopPath $stopPath -TimeoutSeconds $CaseTimeoutSeconds
            if ($null -eq $doneControl -or $doneControl.kind -eq 'stop') {
                throw "Coordinator stopped before $($policy.name) completion"
            }
            $done = $doneControl.value
            $peerFailurePhase = 'peer_completion'
            if ([string]$done.schema -ne
                    'ese.v91.i03-done-command/v1' -or
                [string]$done.case_id -ne $caseId -or
                [string]$done.run_nonce -ne $nonce -or
                [string]$done.policy -ne $policy.name -or
                [int]$done.source_process_id -ne $source.Id -or
                [int]$done.client_process_id -ne
                    [int]$prewarm.client_process_id -or
                [string]$done.candidate_commit -ne $candidate.commit -or
                [string]$done.candidate_emule_sha256 -ne $expectedHash -or
                [int]$done.expected_connection_count -lt 0) {
                throw "Invalid $($policy.name) done command"
            }
            $finalInbound = @(
                Get-I03PeerInboundConnectionSnapshot `
                    -ProcessId $source.Id -LocalPort $PeerTcpPort
            )
            if ([bool]$done.route_observed) {
                $peerFamilies = @(
                    $finalInbound.family | Sort-Object -Unique
                )
                $reportedFamilies = @(
                    $done.observed_families | ForEach-Object {
                        [string]$_
                    } | Sort-Object -Unique
                )
                if ($finalInbound.Count -ne
                        [int]$done.expected_connection_count -or
                    ($peerFamilies -join ',') -ne
                        ($reportedFamilies -join ',')) {
                    Stop-I03PeerProduct `
                        -Code 'WRONG_OR_NONPHYSICAL_SOCKET' `
                        -SourceEvidence ([ordered]@{
                            done = $done
                            final_inbound = $finalInbound
                        }) -Reason 'Peer final inbound socket did not correlate'
                }
            } elseif ($finalInbound.Count -ne 0) {
                Stop-I03PeerProduct `
                    -Code 'WRONG_OR_NONPHYSICAL_SOCKET' `
                    -SourceEvidence ([ordered]@{
                        done = $done
                        final_inbound = $finalInbound
                    }) -Reason 'Peer saw an unreported final connection'
            }
            $peerApi = Get-I03ApiProbe -Port $PeerWebPort
            if (-not $peerApi.available) {
                Stop-I03PeerProduct -Code 'API_UNAVAILABLE' `
                    -SourceEvidence $peerApi `
                    -Reason 'Peer API became unavailable after restart'
            }
            if (-not $peerApi.isolation_valid) {
                Stop-I03PeerProduct -Code 'API_CONTRACT' `
                    -SourceEvidence $peerApi `
                    -Reason 'Peer API isolation contract changed after restart'
            }
            if ((Get-I03UserHashSha256 -NodePath $sourceNode) -ne
                $sourceIdentity) {
                Stop-I03PeerProduct -Code 'PEER_IDENTITY_CHANGED' `
                    -SourceEvidence ([ordered]@{
                        process = $sourceExpectedIdentity
                        expected_identity_sha256 = $sourceIdentity
                    }) -Reason 'Peer identity changed after restart'
            }
            Write-LabJson -Value ([ordered]@{
                schema = 'ese.v91.i03-peer-complete/v1'
                case_id = $caseId
                run_nonce = $nonce
                policy = $policy.name
                candidate_commit = $candidate.commit
                candidate_emule_sha256 = $expectedHash
                source_process_id = $source.Id
                source_process_emule_sha256 = Get-LabSha256 -Path $source.Path
                source_userhash_sha256 = $sourceIdentity
                route_observed = [bool]$done.route_observed
                observed_family = [string]$done.observed_family
                observed_families = @($done.observed_families)
                inbound_connections = $finalInbound
                api = $peerApi
            }) -Path $completePath | Out-Null
            $barriersCompleted++
        }

        $finalStop = Wait-I03JsonFile -Path $stopPath `
            -TimeoutSeconds $CaseTimeoutSeconds
        if ($null -eq $finalStop -or
            [string]$finalStop.value.schema -ne
                'ese.v91.i03-stop-command/v1' -or
            [string]$finalStop.value.case_id -ne $caseId -or
            [string]$finalStop.value.run_nonce -ne $nonce -or
            [string]$finalStop.value.action -ne 'stop-owned-processes' -or
            [string]$finalStop.value.candidate_commit -ne
                $candidate.commit -or
            [string]$finalStop.value.candidate_emule_sha256 -ne
                $expectedHash) {
            throw 'Peer received an invalid final stop command'
        }
    } catch {
        $peerError = $_.Exception.Message
        if ($peerError.StartsWith('I03_LAB_BLOCKED::') -or
            $peerError.StartsWith('I03_PRODUCT_INVARIANT::')) {
            $runtimeFailure = $peerError
        } elseif ($peerError.StartsWith('I03_COLLECTOR::')) {
            $null = Add-I03PeerFailure -Status 'LAB_BLOCKED' `
                -Code 'COLLECTOR_UNAVAILABLE' `
                -Reason 'Peer socket collector failed'
            $runtimeFailure = 'I03_LAB_BLOCKED::COLLECTOR_UNAVAILABLE'
        } else {
            $null = Add-I03PeerFailure -Status 'LAB_BLOCKED' `
                -Code 'HARNESS_EXCEPTION' -Reason $peerError
            $runtimeFailure = 'I03_LAB_BLOCKED::HARNESS_EXCEPTION'
        }
    } finally {
        if ($null -ne $source) {
            $stopped = Stop-I03OwnedProcess -Process $source `
                -ExpectedPath $sourceExe `
                -ExpectedIdentity $sourceExpectedIdentity
            $peerStopped = [bool]$stopped.stopped
            if (-not $stopped.stopped -or -not $stopped.collector_ok -or
                $stopped.unexpected_descendant_count -ne 0) {
                $cleanupFailures.Add('peer source process remains running')
            }
        } else {
            $peerStopped = $true
        }
        if ($null -ne $mutationBaseline) {
            try {
                $mutationCleanup = Complete-I03MutationTransaction `
                    -Baseline $mutationBaseline
                if (-not [bool]$mutationCleanup.complete) {
                    $cleanupFailures.Add(
                        'startup registry or forbidden system state changed'
                    )
                }
            } catch {
                $cleanupFailures.Add(
                    'startup registry/system-state restoration failed'
                )
            }
        } else {
            $cleanupFailures.Add('mutation baseline was not captured')
        }
        try {
            $after = Get-LabCandidateInfo -PackagePath $PackagePath `
                -ExpectedCommit $Commit
            $packageIdentityAfter =
                Get-I03PackageIdentity -PackagePath $candidate.package_path
            $packageZipBindingAfter = Get-I03ZipPackageBinding `
                -ZipPath $candidateZip `
                -ExpectedZipSha256 $expectedZipHash `
                -PackageIdentity $packageIdentityAfter
            Write-LabJson -Value $packageIdentityAfter -Path (
                Join-Path $evidence 'package-manifest-after.json'
            ) | Out-Null
            Write-LabJson -Value $packageZipBindingAfter -Path (
                Join-Path $evidence 'package-zip-binding-after.json'
            ) | Out-Null
            $packageManifestUnchanged =
                $null -ne $packageIdentityBefore -and
                $packageIdentityAfter.manifest_sha256 -eq
                    $packageIdentityBefore.manifest_sha256 -and
                $packageIdentityAfter.file_count -eq
                    $packageIdentityBefore.file_count -and
                $packageIdentityAfter.total_bytes -eq
                    $packageIdentityBefore.total_bytes
            $packageZipBindingUnchanged =
                $null -ne $packageZipBindingBefore -and
                $packageZipBindingAfter.verified -and
                $packageZipBindingAfter.zip_sha256 -eq
                    $packageZipBindingBefore.zip_sha256 -and
                $packageZipBindingAfter.zip_bytes -eq
                    $packageZipBindingBefore.zip_bytes -and
                $packageZipBindingAfter.manifest_sha256 -eq
                    $packageZipBindingBefore.manifest_sha256
            $candidateUnchanged =
                $after.emule_sha256 -eq $expectedHash -and
                $after.ese_server_sha256 -eq $candidate.ese_server_sha256 -and
                $after.build_info_sha256 -eq $candidate.build_info_sha256 -and
                $packageManifestUnchanged -and
                $packageZipBindingUnchanged
        } catch {
            $cleanupFailures.Add(
                "candidate revalidation failed: $($_.Exception.Message)"
            )
        }
        if ($sourceNode -and $null -ne $packageIdentityBefore -and
            (Test-Path -LiteralPath $sourceNode -PathType Container)) {
            $peerNodeTerminalBinding = Test-I03PreparedNodeBinding `
                -NodePath $sourceNode `
                -PackageIdentity $packageIdentityBefore -Phase Terminal
            Write-LabJson -Value $peerNodeTerminalBinding -Path (
                Join-Path $evidence 'prepared-node-binding-terminal.json'
            ) | Out-Null
            $nodeUnchanged =
                [bool]$peerNodeTerminalBinding.collector_ok -and
                [bool]$peerNodeTerminalBinding.bound
        }
        if (-not $candidateUnchanged) {
            $cleanupFailures.Add('candidate package changed during peer run')
        }
        if (-not $nodeUnchanged) {
            $cleanupFailures.Add('prepared peer static program files changed')
        }
    }

    $peerTerminalNetwork = Get-I03TerminalSocketCleanupEvidence `
        -Ports @(
            $PeerTcpPort, $PeerUdpPort, $PeerWebPort,
            $AutoTcpPort, $AutoUdpPort, $AutoWebPort,
            $PreferredTcpPort, $PreferredUdpPort, $PreferredWebPort
        ) -OwnedProcessIds @($peerOwnedProcessIds)
    Write-LabJson -Value $peerTerminalNetwork -Path (
        Join-Path $evidence 'terminal-network-cleanup.json'
    ) | Out-Null
    if (-not [bool]$peerTerminalNetwork.collector_ok -or
        -not [bool]$peerTerminalNetwork.complete) {
        $cleanupFailures.Add('peer terminal network cleanup is incomplete')
    }
    $peerTerminalProcesses = Get-I03EmuleProcessCensus
    Write-LabJson -Value $peerTerminalProcesses -Path (
        Join-Path $evidence 'terminal-emule-process-census.json'
    ) | Out-Null
    if (-not [bool]$peerTerminalProcesses.collector_ok -or
        [int]$peerTerminalProcesses.process_count -ne 0) {
        $cleanupFailures.Add('peer terminal eMule process census is not empty')
    }
    $peerFailureSourceVerification = Test-I03PersistedFailureSources `
        -Manifest @($peerFailureSourceFiles) -Root $coordination `
        -ExpectedCaseId $caseId -ExpectedRunNonce $nonce `
        -ExpectedRole 'Peer'
    $peerReferencedSourceHashes = @($peerFailureRecords |
        Where-Object status -CEQ 'PRODUCT_INVARIANT' |
        ForEach-Object { $_.proofs } | ForEach-Object {
            [string]$_.source_evidence_sha256
        } | Sort-Object -Unique)
    $peerReferencedBindingHashes = @($peerFailureRecords |
        Where-Object status -CEQ 'PRODUCT_INVARIANT' |
        ForEach-Object { $_.proofs } | ForEach-Object {
            [string]$_.binding_sha256
        } | Sort-Object -Unique)
    $peerVerifiedSourceHashes = @(
        $peerFailureSourceVerification.source_sha256
    )
    $peerVerifiedBindingHashes = @(
        $peerFailureSourceVerification.trusted_binding_sha256
    )
    if (-not [bool]$peerFailureSourceVerification.ok -or
        @($peerReferencedSourceHashes | Where-Object {
                [string]$_ -cnotin $peerVerifiedSourceHashes
            }).Count -gt 0 -or
        @($peerVerifiedSourceHashes | Where-Object {
                [string]$_ -cnotin $peerReferencedSourceHashes
            }).Count -gt 0 -or
        @($peerReferencedBindingHashes | Where-Object {
                [string]$_ -cnotin $peerVerifiedBindingHashes
            }).Count -gt 0 -or
        @($peerVerifiedBindingHashes | Where-Object {
                [string]$_ -cnotin $peerReferencedBindingHashes
            }).Count -gt 0) {
        $cleanupFailures.Add('peer failure-source evidence is incomplete')
    }
    if ($cleanupFailures.Count -gt 0) {
        $peerCurrentPolicy = 'none'
        $peerFailurePhase = 'cleanup'
        $peerFixtureCertified = $false
        $null = Add-I03PeerFailure -Status 'LAB_BLOCKED' `
            -Code 'CLEANUP_INCOMPLETE' `
            -Reason 'Peer transactional cleanup was incomplete'
    }
    $peerCleanupComplete = $peerStopped -and $candidateUnchanged -and
        $nodeUnchanged -and $null -ne $mutationCleanup -and
        [bool]$mutationCleanup.complete -and
        [bool]$peerTerminalNetwork.complete -and
        [bool]$peerTerminalProcesses.collector_ok -and
        [int]$peerTerminalProcesses.process_count -eq 0 -and
        $cleanupFailures.Count -eq 0
    [object[]]$peerCleanupIncidentCodes = @()
    if ($cleanupFailures.Count -gt 0) {
        $peerCleanupIncidentCodes = @('CLEANUP_INCOMPLETE')
    }
    foreach ($failureRecord in $peerFailureRecords) {
        $failureRecord.cleanup.complete = $peerCleanupComplete
        $failureRecord.cleanup.incident_codes =
            [object[]]$peerCleanupIncidentCodes
    }
    $peerHasProductFailure = @($peerFailureRecords | Where-Object {
        [string]$_.status -ceq 'PRODUCT_INVARIANT'
    }).Count -gt 0
    $peerStatus = if ($peerHasProductFailure) {
        'PRODUCT_INVARIANT'
    } elseif ($null -eq $runtimeFailure -and
        $barriersCompleted -eq 2 -and $peerStopped -and
        $cleanupFailures.Count -eq 0) { 'COMPLETE' } else { 'LAB_BLOCKED' }
    $peerResult = [ordered]@{
        schema = 'ese.v91.i03-peer-result/v1'
        case_id = $caseId
        run_nonce = $nonce
        generated_at_utc = Get-LabUtcTimestamp
        status = $peerStatus
        candidate_commit = $candidate.commit
        candidate_emule_sha256 = $expectedHash
        candidate_zip_sha256 = $expectedZipHash
        candidate_package_manifest_sha256 = if (
            $null -eq $packageIdentityBefore
        ) { '' } else { $packageIdentityBefore.manifest_sha256 }
        lab_user_sid_sha256 = $currentLabSidHash
        source_userhash_sha256 = $sourceIdentity
        barriers_completed = $barriersCompleted
        expected_barriers = 2
        last_source_process_id = $currentSourcePid
        topology = $peerTopology
        fixture = $fixture
        runtime_error = $runtimeFailure
        failure_records = @($peerFailureRecords)
        failure_source_manifest = @($peerFailureSourceFiles)
        failure_source_verification = $peerFailureSourceVerification
        cleanup = [ordered]@{
            source_process_stopped = $peerStopped
            candidate_package_unchanged = $candidateUnchanged
            extracted_package_manifest_unchanged =
                $packageManifestUnchanged
            package_zip_binding_unchanged =
                $packageZipBindingUnchanged
            prepared_executable_unchanged = $nodeUnchanged
            prepared_node_initial_binding = $peerNodeInitialBinding
            prepared_node_terminal_binding = $peerNodeTerminalBinding
            mutation_cleanup = $mutationCleanup
            autostart_restored_exact = $null -ne $mutationCleanup -and
                [bool]$mutationCleanup.autostart_restored_exact
            ed2k_association_restored_exact =
                $null -ne $mutationCleanup -and
                [bool]$mutationCleanup.ed2k_association_restored_exact
            forbidden_state_unchanged = $null -ne $mutationCleanup -and
                [bool]$mutationCleanup.forbidden_state_unchanged
            terminal_network = $peerTerminalNetwork
            terminal_processes = $peerTerminalProcesses
            failures = @($cleanupFailures)
            retained_by_design = @('peer OutputRoot profile', 'fixture', 'evidence')
        }
    }
    Write-LabJson -Value $peerResult `
        -Path (Join-Path $evidence 'peer-result.json') | Out-Null
    Write-LabJson -Value $peerResult -Path $peerResultPath | Out-Null
    $peerPrivateManifestPath = Join-Path $evidence 'private-manifest.json'
    $peerPublicRootPrefix = [IO.Path]::GetFullPath(
        $publicEvidence
    ).TrimEnd('\') + '\'
    $peerOutputRootPrefix = [IO.Path]::GetFullPath($output).TrimEnd('\') + '\'
    $peerCoordinationRootPrefix = [IO.Path]::GetFullPath(
        $coordination
    ).TrimEnd('\') + '\'
    $peerOutputRows = @(Get-ChildItem -LiteralPath $output -File `
        -Recurse -Force -ErrorAction Stop | Where-Object {
            -not $_.FullName.StartsWith(
                $peerPublicRootPrefix,
                [StringComparison]::OrdinalIgnoreCase
            ) -and $_.FullName -cne $peerPrivateManifestPath
        } | ForEach-Object {
            [pscustomobject][ordered]@{
                scope = 'output-private-and-nodes'
                relative_path = $_.FullName.Substring(
                    $peerOutputRootPrefix.Length
                )
                bytes = [Int64]$_.Length
                sha256 = Get-LabSha256 -Path $_.FullName
            }
        })
    $peerCoordinationRows = @(Get-ChildItem -LiteralPath $coordination `
        -File -Recurse -Force -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    scope = 'coordination-private'
                    relative_path = $_.FullName.Substring(
                        $peerCoordinationRootPrefix.Length
                    )
                    bytes = [Int64]$_.Length
                    sha256 = Get-LabSha256 -Path $_.FullName
                }
            })
    $peerPrivateRows = @(
        @($peerOutputRows) + @($peerCoordinationRows) |
            Sort-Object scope, relative_path
    )
    Write-LabJson -Value ([ordered]@{
        schema = 'ese.v91.i03-private-evidence-manifest/v1'
        case_id = $caseId
        run_nonce = $nonce
        role = 'Peer'
        retained_by_design = $true
        files = $peerPrivateRows
    }) -Path $peerPrivateManifestPath | Out-Null
    $peerPublicSummary = [ordered]@{
        schema = 'ese.v91.i03-peer-public-summary/v1'
        case_id = $caseId
        role = 'Peer'
        status = $peerStatus
        candidate = [ordered]@{
            commit = $candidate.commit
            emule_sha256 = $expectedHash
            zip_sha256 = $expectedZipHash
            package_unchanged = $candidateUnchanged
        }
        barriers_completed = $barriersCompleted
        expected_barriers = 2
        failures = @($peerFailureRecords | ForEach-Object {
            [pscustomobject][ordered]@{
                policy = [string]$_.policy
                phase = [string]$_.phase
                status = [string]$_.status
                category = [string]$_.category
                code = [string]$_.code
                fixture_certified = [bool]$_.fixture_certified
                cleanup_complete = [bool]$_.cleanup.complete
            }
        })
        cleanup = [ordered]@{
            complete = $peerCleanupComplete
            source_process_stopped = $peerStopped
            candidate_package_unchanged = $candidateUnchanged
            registry_and_system_state_exact =
                $null -ne $mutationCleanup -and
                [bool]$mutationCleanup.complete
        }
        retention = [ordered]@{
            private_artifacts_retained = $true
            coordination_private_artifacts_retained = $true
            private_file_count = $peerPrivateRows.Count + 1
            private_artifact_manifest_sha256 =
                Get-LabSha256 -Path $peerPrivateManifestPath
        }
    }
    if (-not (Test-I03PublicEvidenceObject -Value $peerPublicSummary)) {
        throw 'I03_PUBLIC_EVIDENCE::PEER_SUMMARY_REJECTED'
    }
    $peerPublicSummaryPath = Join-Path $publicEvidence 'summary.json'
    Write-LabJson -Value $peerPublicSummary `
        -Path $peerPublicSummaryPath | Out-Null
    $peerPublicManifest = [ordered]@{
        schema = 'ese.v91.i03-public-evidence-manifest/v1'
        case_id = $caseId
        role = 'Peer'
        files = @([ordered]@{
            name = 'summary.json'
            bytes = [Int64](Get-Item -LiteralPath `
                $peerPublicSummaryPath).Length
            sha256 = Get-LabSha256 -Path $peerPublicSummaryPath
        })
        private_artifacts_retained = $true
        private_artifact_manifest_sha256 =
            Get-LabSha256 -Path $peerPrivateManifestPath
        public_scan_passed = $true
    }
    if (-not (Test-I03PublicEvidenceObject -Value $peerPublicManifest)) {
        throw 'I03_PUBLIC_EVIDENCE::PEER_MANIFEST_REJECTED'
    }
    $peerPublicManifestPath = Join-Path $publicEvidence `
        'evidence-manifest.json'
    Write-LabJson -Value $peerPublicManifest `
        -Path $peerPublicManifestPath | Out-Null
    if (-not (Test-I03PublicEvidenceText -Text (
            Get-Content -LiteralPath $peerPublicSummaryPath -Raw
        )) -or -not (Test-I03PublicEvidenceText -Text (
            Get-Content -LiteralPath $peerPublicManifestPath -Raw
        )) -or -not (Test-I03PublicEvidenceDirectory `
            -Root $publicEvidence `
            -ExpectedFiles @('summary.json', 'evidence-manifest.json') `
            -PrivateManifestPath $peerPrivateManifestPath)) {
        throw 'I03_PUBLIC_EVIDENCE::PEER_POSTWRITE_SCAN_FAILED'
    }
    Write-Host "V91-I03 peer status: $peerStatus" -ForegroundColor $(
        if ($peerStatus -eq 'COMPLETE') { 'Green' } else { 'Yellow' }
    )
    if ($peerStatus -eq 'COMPLETE') { exit 0 }
    exit 2
}

function Invoke-I03CoordinatorRole {
    if (-not (Test-I03Administrator)) {
        throw 'Coordinator role requires an elevated PowerShell for complete PID/socket evidence'
    }
    if (-not $RunNonce) {
        $script:RunNonce = [Guid]::NewGuid().ToString('N')
    }
    $nonce = $RunNonce.ToLowerInvariant()
    $startedAt = [DateTime]::UtcNow
    $repositoryRoot = Get-LabFullPath -Path (
        Join-Path $PSScriptRoot '..\..'
    )
    $outputPath = Assert-I03PrivateRoot -Path $OutputRoot `
        -Label 'OUTPUT' -RepositoryRoot $repositoryRoot `
        -CandidatePackageRoot $candidate.package_path
    $coordinationRootPath = Assert-I03PrivateRoot `
        -Path $CoordinationRoot -Label 'COORDINATION' `
        -RepositoryRoot $repositoryRoot `
        -CandidatePackageRoot $candidate.package_path
    if ((Test-I03PathContainedBy -Path $outputPath `
            -Root $coordinationRootPath) -or
        (Test-I03PathContainedBy -Path $coordinationRootPath `
            -Root $outputPath)) {
        throw 'I03_PRIVATE_ROOT::OUTPUT_COORDINATION_OVERLAP'
    }
    $packageRootWithSeparator =
        (Get-LabFullPath -Path $candidate.package_path).TrimEnd('\') + '\'
    if (($outputPath.TrimEnd('\') + '\').StartsWith(
        $packageRootWithSeparator,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'Coordinator OutputRoot must not be inside the candidate package'
    }
    if (Test-Path -LiteralPath $outputPath) {
        if (@(Get-ChildItem -LiteralPath $outputPath -Force).Count -ne 0) {
            throw "Coordinator OutputRoot must be absent or empty: $outputPath"
        }
    }
    $output = New-LabDirectory -Path $outputPath
    $evidence = New-LabDirectory -Path (Join-Path $output 'private')
    $publicEvidence = New-LabDirectory -Path (Join-Path $output 'evidence')
    $nodes = New-LabDirectory -Path (Join-Path $output 'nodes')
    $privateSummaryPath = Join-Path $evidence 'summary.json'
    $summaryPath = Join-Path $publicEvidence 'summary.json'
    $cleanupPath = Join-Path $evidence 'cleanup.json'
    $manualPath = Join-Path $evidence 'MANUAL-PEER-COMMAND.txt'
    $coordination = Get-LabFullPath -Path (Join-Path `
        $coordinationRootPath "v91-i03-$nonce")
    if (($coordination.TrimEnd('\') + '\').StartsWith(
        $packageRootWithSeparator,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'Coordinator CoordinationRoot must not be inside the candidate package'
    }
    if (Test-Path -LiteralPath $coordination) {
        throw "Coordinator run directory must be fresh/absent: $coordination"
    }
    $null = New-LabDirectory -Path (Split-Path -Parent $coordination)
    $null = New-Item -ItemType Directory -Path $coordination `
        -ErrorAction Stop

    $runPath = Join-Path $coordination 'run.json'
    $readyPath = Join-Path $coordination 'peer-ready.json'
    $baselineCommandPath = Join-Path $coordination 'baseline.json'
    $baselineAckPath = Join-Path $coordination 'peer-baseline-ack.json'
    $stopPath = Join-Path $coordination 'stop.json'
    $peerResultPath = Join-Path $coordination 'peer-result.json'

    $blockedReasons = [System.Collections.Generic.List[string]]::new()
    $productFailures = [System.Collections.Generic.List[object]]::new()
    $failureRecords = [System.Collections.Generic.List[object]]::new()
    $failureSourceFiles = [System.Collections.Generic.List[object]]::new()
    $trustedProofBindings =
        [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal
        )
    $cleanupFailures = [System.Collections.Generic.List[string]]::new()
    $caseResults = [System.Collections.Generic.List[object]]::new()
    $preparedBinaries = [System.Collections.Generic.List[object]]::new()
    $ownedCandidateProcessIds =
        [System.Collections.Generic.HashSet[int]]::new()
    $controlledServerPorts =
        [System.Collections.Generic.HashSet[int]]::new()
    $profileIdentityHashes =
        [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
    $runtimeFailure = $null
    $peerReady = $null
    $peerResult = $null
    $peerReadyExact = $false
    $peerResultExact = $false
    $peerCleanupExact = $false
    $peerFailureProtocolExact = $false
    $peerFailureSourceVerification = $null
    $peerProvenProductFailure = $false
    $peerStopWritten = $false
    $baselineProbeV4 = $null
    $baselineProbeV6 = $null
    $baselineEvidence = $null
    $clockEvidence = $null
    $routeV4 = $null
    $routeV6 = $null
    $localV4 = $null
    $localV6 = $null
    $topologyLocalValid = $false
    $topologyT1 = $false
    $topologyT2 = $false
    $topologyValid = $false
    $topologyClass = ''
    $sameIPv4PhysicalPrefix = $false
    $sameIPv6PhysicalPrefix = $false
    $currentPeerPid = 0
    $sourceIdentity = ''
    $activeClient = $null
    $activeClientExe = ''
    $activeClientExpectedIdentity = $null
    $activeServer = $null
    $remoteJob = $null
    $candidateAfter = $null
    $candidateUnchanged = $false
    $packageIdentityBefore = $null
    $packageIdentityAfter = $null
    $packageManifestUnchanged = $false
    $packageZipBindingBefore = $null
    $packageZipBindingAfter = $null
    $packageZipBindingUnchanged = $false
    $mutationBaseline = $null
    $mutationCleanup = $null
    $terminalNetworkCleanup = $null
    $allClientsStopped = $true
    $allControlServersStopped = $true
    $currentPolicyName = 'none'
    $currentFailurePhase = 'preflight'
    $currentFixtureCertified = $false
    $productAdjudication = [ordered]@{
        runtime_failure = $false
        reason = ''
    }

    function Add-I03BlockedReason {
        param([Parameter(Mandatory = $true)][string]$Reason)
        if (-not $blockedReasons.Contains($Reason)) {
            $blockedReasons.Add($Reason)
        }
    }

    function Get-I03FailureCategory {
        param(
            [Parameter(Mandatory = $true)][string]$Status,
            [Parameter(Mandatory = $true)][string]$Code
        )
        $product = [ordered]@{
            CANDIDATE_EXITED = 'PRODUCT_RUNTIME'
            UI_UNRESPONSIVE = 'PRODUCT_LIVENESS'
            API_UNAVAILABLE = 'PRODUCT_LIVENESS'
            API_CONTRACT = 'PRODUCT_CONTRACT'
            LINK_REJECTED = 'PRODUCT_INPUT'
            IPV4_PREWARM_INVARIANT = 'PRODUCT_ROUTE'
            PEER_IDENTITY_CHANGED = 'PRODUCT_IDENTITY'
            NO_ROUTE = 'PRODUCT_ROUTE'
            WRONG_FAMILY = 'PRODUCT_ROUTE'
            DUPLICATE_ROUTE = 'PRODUCT_ROUTE'
            WRONG_OR_NONPHYSICAL_SOCKET = 'PRODUCT_ATTRIBUTION'
            CANDIDATE_THIRD_PARTY_SOCKET = 'PRODUCT_ATTRIBUTION'
        }
        $lab = [ordered]@{
            PACKAGE_BINDING = 'LAB_PACKAGE'
            TOPOLOGY = 'LAB_TOPOLOGY'
            CLOCK = 'LAB_CLOCK'
            CONTROL_TIMEOUT = 'LAB_CONTROL'
            COORDINATION_SCHEMA = 'LAB_CONTROL'
            COLLECTOR_UNAVAILABLE = 'LAB_COLLECTOR'
            COLLECTOR_AMBIGUOUS = 'LAB_COLLECTOR'
            EXTERNAL_CONTAMINATION = 'LAB_CONTAMINATION'
            EVIDENCE_INCOMPLETE = 'LAB_EVIDENCE'
            CLEANUP_INCOMPLETE = 'LAB_CLEANUP'
            HARNESS_EXCEPTION = 'LAB_HARNESS'
        }
        $map = if ($Status -ceq 'PRODUCT_INVARIANT') {
            $product
        } else { $lab }
        if (-not $map.Contains($Code)) {
            throw 'I03_FAILURE_PROTOCOL::UNKNOWN_CODE'
        }
        return [string]$map[$Code]
    }

    function Add-I03TypedFailure {
        param(
            [Parameter(Mandatory = $true)][string]$Status,
            [Parameter(Mandatory = $true)][string]$Code,
            [Parameter(Mandatory = $true)][string]$Reason,
            [object[]]$Proofs = @()
        )
        if ($null -eq $packageIdentityBefore) { return $null }
        $record = New-I03FailureRecord `
            -CaseId $caseId -RunNonce $nonce -Role 'Coordinator' `
            -Policy $currentPolicyName -Phase $currentFailurePhase `
            -Status $Status `
            -Category (Get-I03FailureCategory -Status $Status -Code $Code) `
            -Code $Code -Message $Reason `
            -CandidateCommit $candidate.commit `
            -CandidateEmuleSha256 $expectedHash `
            -CandidateZipSha256 $expectedZipHash `
            -PackageManifestSha256 $packageIdentityBefore.manifest_sha256 `
            -FixtureCertified $currentFixtureCertified -Proofs $Proofs
        $failureRecords.Add($record)
        return $record
    }

    function Stop-I03Fixture {
        param(
            [Parameter(Mandatory = $true)][string]$Reason,
            [ValidateSet(
                'PACKAGE_BINDING', 'TOPOLOGY', 'CLOCK',
                'CONTROL_TIMEOUT', 'COORDINATION_SCHEMA',
                'COLLECTOR_UNAVAILABLE', 'COLLECTOR_AMBIGUOUS',
                'EXTERNAL_CONTAMINATION', 'EVIDENCE_INCOMPLETE',
                'CLEANUP_INCOMPLETE', 'HARNESS_EXCEPTION'
            )][string]$Code = 'HARNESS_EXCEPTION'
        )
        Add-I03BlockedReason -Reason $Code
        $null = Add-I03TypedFailure -Status 'LAB_BLOCKED' `
            -Code $Code -Reason $Reason
        throw "I03_LAB_BLOCKED::$Code"
    }

    function Add-I03ProductFailure {
        param(
            [Parameter(Mandatory = $true)]
            [ValidateSet(
                'CANDIDATE_EXITED', 'UI_UNRESPONSIVE',
                'API_UNAVAILABLE', 'API_CONTRACT', 'LINK_REJECTED',
                'IPV4_PREWARM_INVARIANT', 'PEER_IDENTITY_CHANGED',
                'NO_ROUTE', 'WRONG_FAMILY', 'DUPLICATE_ROUTE',
                'WRONG_OR_NONPHYSICAL_SOCKET',
                'CANDIDATE_THIRD_PARTY_SOCKET'
            )][string]$Code,
            [Parameter(Mandatory = $true)][string]$Reason,
            [Parameter(Mandatory = $true)][AllowNull()][object]$SourceEvidence
        )
        if (-not $currentFixtureCertified -or
            $currentPolicyName -notin @('auto', 'preferred')) {
            Stop-I03Fixture -Code 'EVIDENCE_INCOMPLETE' `
                -Reason 'Product classification attempted before fixture certification'
        }
        $sourceName = 'failure-source-{0:D3}.json' -f (
            $failureSourceFiles.Count + 1
        )
        $sourcePath = Join-Path $evidence $sourceName
        try {
            Write-LabJson -Value ([ordered]@{
                schema = 'ese.v91.i03-failure-source/v1'
                case_id = $caseId
                run_nonce = $nonce
                role = 'Coordinator'
                policy = $currentPolicyName
                phase = $currentFailurePhase
                code = $Code
                evidence = $SourceEvidence
            }) -Path $sourcePath | Out-Null
            $sourceHash = Get-LabSha256 -Path $sourcePath
            $sourceLength = (Get-Item -LiteralPath $sourcePath `
                -Force -ErrorAction Stop).Length
            $verifiedSource = Get-Content -LiteralPath $sourcePath -Raw `
                -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if ([string]$verifiedSource.schema -cne
                    'ese.v91.i03-failure-source/v1' -or
                [string]$verifiedSource.case_id -cne $caseId -or
                [string]$verifiedSource.run_nonce -cne $nonce -or
                [string]$verifiedSource.policy -cne $currentPolicyName -or
                [string]$verifiedSource.phase -cne $currentFailurePhase -or
                [string]$verifiedSource.code -cne $Code -or
                (Get-LabSha256 -Path $sourcePath) -cne $sourceHash) {
                throw 'I03_FAILURE_SOURCE::VERIFY_FAILED'
            }
            $failureSourceFiles.Add([pscustomobject][ordered]@{
                file_name = $sourceName
                sha256 = $sourceHash
                bytes = [Int64]$sourceLength
            })
        } catch {
            Stop-I03Fixture -Code 'EVIDENCE_INCOMPLETE' `
                -Reason 'Product failure source could not be persisted and verified'
        }
        $proof = New-I03ProofProjection -Kind ($Code.ToLowerInvariant()) `
            -CaseId $caseId -RunNonce $nonce -Role 'Coordinator' `
            -Policy $currentPolicyName -Phase $currentFailurePhase `
            -SourceEvidenceSha256 $sourceHash
        [void]$trustedProofBindings.Add([string]$proof.binding_sha256)
        $record = Add-I03TypedFailure -Status 'PRODUCT_INVARIANT' `
            -Code $Code -Reason $Reason -Proofs @($proof)
        if ($null -eq $record) {
            throw 'I03_LAB_BLOCKED::EVIDENCE_INCOMPLETE'
        }
        $productFailures.Add($record)
        $productAdjudication.runtime_failure = $true
        $productAdjudication.reason = $Code
        return $record
    }

    function Stop-I03ProductFailure {
        param(
            [Parameter(Mandatory = $true)][string]$Code,
            [Parameter(Mandatory = $true)][string]$Reason,
            [Parameter(Mandatory = $true)][AllowNull()][object]$SourceEvidence
        )
        $null = Add-I03ProductFailure -Code $Code -Reason $Reason `
            -SourceEvidence $SourceEvidence
        throw "I03_PRODUCT_INVARIANT::$Code"
    }

    function Wait-I03OwnedTupleGone {
        param(
            [Parameter(Mandatory = $true)][int]$ProcessId,
            [Parameter(Mandatory = $true)][string]$TupleKey,
            [ValidateRange(1, 30)][int]$TimeoutSeconds = 10
        )
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        do {
            $present = @(
                Get-I03TargetConnections | Where-Object {
                    [int]$_.owning_process -eq $ProcessId -and
                    [string]$_.tuple_key -eq $TupleKey -and
                    [string]$_.state -in @('SynSent', 'Established')
                }
            ).Count -gt 0
            if (-not $present) { return $true }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $deadline)
        return $false
    }

    try {
        $packageIdentityBefore =
            Get-I03PackageIdentity -PackagePath $candidate.package_path
        $packageZipBindingBefore = Get-I03ZipPackageBinding `
            -ZipPath $candidateZip -ExpectedZipSha256 $expectedZipHash `
            -PackageIdentity $packageIdentityBefore
        Write-LabJson -Value $packageIdentityBefore -Path (
            Join-Path $evidence 'package-manifest-before.json'
        ) | Out-Null
        Write-LabJson -Value $packageZipBindingBefore -Path (
            Join-Path $evidence 'package-zip-binding-before.json'
        ) | Out-Null
        $preexistingProcesses = Get-I03EmuleProcessCensus
        Write-LabJson -Value $preexistingProcesses -Path (
            Join-Path $evidence 'preexisting-emule-process-census.json'
        ) | Out-Null
        if (-not [bool]$preexistingProcesses.collector_ok) {
            Stop-I03Fixture -Code 'COLLECTOR_UNAVAILABLE' `
                -Reason 'Preexisting eMule process collector failed'
        }
        if ([int]$preexistingProcesses.process_count -ne 0) {
            Stop-I03Fixture -Code 'EXTERNAL_CONTAMINATION' `
                -Reason 'Preexisting eMule process detected on coordinator'
        }
        Test-I03PortSetFree -Ports @(
            $AutoTcpPort, $AutoUdpPort, $AutoWebPort,
            $PreferredTcpPort, $PreferredUdpPort, $PreferredWebPort
        )
        $routeV4 = Get-I03RouteEvidence -RemoteAddress $peerV4Text
        $routeV6 = Get-I03RouteEvidence -RemoteAddress $peerV6Text
        if (-not $routeV4.available -or -not $routeV6.available) {
            Stop-I03Fixture `
                -Reason 'Coordinator lacks a real route to both peer families'
        }
        $localV4 = Get-I03AssignedAddress `
            -Address ([string]$routeV4.source_address) `
            -Family ([Net.Sockets.AddressFamily]::InterNetwork) `
            -Context 'coordinator-route-ipv4'
        $localV6 = Get-I03AssignedAddress `
            -Address ([string]$routeV6.source_address) `
            -Family ([Net.Sockets.AddressFamily]::InterNetworkV6) `
            -Context 'coordinator-route-ipv6'
        $topologyLocalValid =
            [bool]$routeV4.adapter.physical_nonvirtual -and
            [bool]$routeV6.adapter.physical_nonvirtual -and
            [int]$routeV4.interface_index -eq
                [int]$routeV6.interface_index -and
            [int]$routeV4.interface_index -eq
                [int]$localV4.interface_index -and
            [int]$routeV6.interface_index -eq
                [int]$localV6.interface_index -and
            [string]$routeV6.source_class -eq 'global-native-v6' -and
            [string]$routeV6.remote_class -eq 'global-native-v6'
        if (-not $topologyLocalValid) {
            Stop-I03Fixture -Reason (
                'Coordinator IPv4/IPv6 routes are not on one Up physical ' +
                'non-virtual interface'
            )
        }
        $localMachineIdentity = Get-I03MachineIdentityEvidence
        if (-not [bool]$localMachineIdentity.physical_host_claim -or
            [bool]$localMachineIdentity.virtual_signature_detected) {
            Stop-I03Fixture -Code 'TOPOLOGY' -Reason (
                'Coordinator Win32_ComputerSystem identifies a virtual host'
            )
        }
        $localMachineId = [string]$localMachineIdentity.machine_id_sha256
        $runManifest = [ordered]@{
            schema = 'ese.v91.i03-run/v1'
            case_id = $caseId
            run_nonce = $nonce
            created_at_utc = Get-LabUtcTimestamp
            lab_account = [ordered]@{
                disposable_account_acknowledged =
                    [bool]$DisposableLabAccountAcknowledged
                coordinator_user_sid_sha256 = $currentLabSidHash
            }
            candidate = [ordered]@{
                commit = $candidate.commit
                version = $candidate.version
                emule_sha256 = $expectedHash
                ese_server_sha256 = $candidate.ese_server_sha256
                build_info_sha256 = $candidate.build_info_sha256
                zip_sha256 = $packageZipBindingBefore.zip_sha256
                zip_bytes = $packageZipBindingBefore.zip_bytes
                package_manifest_sha256 =
                    $packageIdentityBefore.manifest_sha256
                package_file_count = $packageIdentityBefore.file_count
                package_total_bytes = $packageIdentityBefore.total_bytes
            }
            peer = [ordered]@{
                public_ipv4 = $peerV4Text
                local_ipv4 = $peerLocalV4Text
                public_ipv6 = $peerV6Text
                tcp_port = $PeerTcpPort
                udp_port = $PeerUdpPort
                web_port = $PeerWebPort
            }
            coordinator = [ordered]@{
                machine_id_sha256 = $localMachineId
                machine_identity = $localMachineIdentity
                route_ipv4_source = $routeV4.source_address
                route_ipv6_source = $routeV6.source_address
                interface_index = $routeV4.interface_index
            }
            clients = @(
                [ordered]@{
                    policy = 'auto'
                    ipv6_mode = 1
                    expected_family = 'IPv4'
                    tcp_port = $AutoTcpPort
                    udp_port = $AutoUdpPort
                    web_port = $AutoWebPort
                },
                [ordered]@{
                    policy = 'preferred'
                    ipv6_mode = 2
                    expected_family = 'IPv6'
                    tcp_port = $PreferredTcpPort
                    udp_port = $PreferredUdpPort
                    web_port = $PreferredWebPort
                }
            )
            file_size_bytes = $FileSizeBytes
            transfer_backlog_control = [ordered]@{
                peer_max_upload_kib_per_second =
                    $peerUploadCapKiBps
                compression_disabled_extension = '.zip'
                minimum_required_backlog_bytes = 64MB
            }
            scheduler_control = [ordered]@{
                type = 'same-host physical-IP minimal eD2K server'
                dynamic_port_per_case = $true
                literal_address = $routeV4.source_address
                idchange_high_id = [uint32]0x01000001
                dns_used = $false
                third_party_servers = $false
            }
            forbidden_mutations = @(
                'adapters', 'routes', 'DNS', 'hosts file', 'firewall'
            )
        }
        $coordinatorAutostartHashes = @(
            'auto', 'preferred' | ForEach-Object {
                $plannedExe = Join-Path $nodes `
                    "v91-i03-$_-b\emule.exe"
                Get-LabStringSha256 -Value (
                    (Get-LabFullPath -Path $plannedExe) + ' -AutoStart'
                )
            }
        )
        $mutationBaseline = Get-I03MutationBaseline `
            -AllowedAutostartValueSha256 $coordinatorAutostartHashes
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i03-transaction-active/v1'
            case_id = $caseId
            run_nonce = $nonce
            role = 'Coordinator'
            candidate_commit = $candidate.commit
            candidate_emule_sha256 = $expectedHash
            candidate_zip_sha256 = $expectedZipHash
            package_manifest_sha256 =
                $packageIdentityBefore.manifest_sha256
            lab_user_sid_sha256 = $currentLabSidHash
            forbidden_state_digests =
                $mutationBaseline.forbidden_state
            autostart_state_sha256 =
                $mutationBaseline.autostart.state_sha256
            run_key_state_sha256 =
                $mutationBaseline.run_key.state_sha256
            ed2k_association_state_sha256 =
                $mutationBaseline.ed2k_association.state_sha256
        }) -Path (Join-Path $evidence 'transaction-active.json') | Out-Null
        Write-LabJson -Value $runManifest -Path $runPath | Out-Null
        Write-LabJson -Value $runManifest `
            -Path (Join-Path $evidence 'run.json') | Out-Null
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i03-preflight/v1'
            captured_at_utc = Get-LabUtcTimestamp
            candidate = $candidate
            local_machine_id_sha256 = $localMachineId
            local_machine_identity = $localMachineIdentity
            routes = @($routeV4, $routeV6)
            local_addresses = @($localV4, $localV6)
            topology_local_valid = $topologyLocalValid
            existing_emule_processes = @(
                $preexistingProcesses.rows
            )
            planned_mutations = @(
                'isolated profile copies',
                'same-host controlled eD2K scheduler server',
                'owned candidate processes',
                'nonce-scoped coordination files'
            )
            forbidden_and_unmodified = @(
                'adapters', 'routes', 'DNS settings/cache', 'hosts file',
                'firewall'
            )
        }) -Path (Join-Path $evidence 'preflight.json') | Out-Null

        $manualCommand = @"
Run this in an elevated PowerShell on the controlled physical peer while the
coordinator waits:

& '$PSCommandPath' ``
  -Role Peer ``
  -PackagePath '<exact-package-on-peer>' ``
  -CandidateZipPath '<matching-candidate-zip-on-peer>' ``
  -ExpectedCandidateZipSha256 '$expectedZipHash' ``
  -OutputRoot '<new-empty-peer-output-root>' ``
  -Commit '$($candidate.commit)' ``
  -ExpectedEmuleSha256 '$expectedHash' ``
  -PeerIPv4 '$peerV4Text' ``
  -PeerLocalIPv4 '$peerLocalV4Text' ``
  -PeerIPv6 '$peerV6Text' ``
  -CoordinationRoot '$CoordinationRoot' ``
  -ControlledPeerAcknowledged ``
  -DisposableLabAccountAcknowledged ``
  -ExpectedLabUserSidSha256 '<peer-current-user-sid-sha256>' ``
  -PeerTcpPort $PeerTcpPort -PeerUdpPort $PeerUdpPort ``
  -PeerWebPort $PeerWebPort ``
  -AutoTcpPort $AutoTcpPort -AutoUdpPort $AutoUdpPort ``
  -AutoWebPort $AutoWebPort ``
  -PreferredTcpPort $PreferredTcpPort ``
  -PreferredUdpPort $PreferredUdpPort ``
  -PreferredWebPort $PreferredWebPort ``
  -FileSizeBytes $FileSizeBytes ``
  -PeerReadyTimeoutSeconds $PeerReadyTimeoutSeconds ``
  -CaseTimeoutSeconds $CaseTimeoutSeconds ``
  -StableObservationSeconds $StableObservationSeconds ``
  -RunNonce '$nonce'

The CoordinationRoot must resolve to this same shared directory on both hosts.
No adapter, route, DNS, hosts or firewall change is part of V91-I03.
"@
        Write-LabText -Value $manualCommand -Path $manualPath | Out-Null
        Write-Host $manualCommand -ForegroundColor Yellow

        $readyWait = Wait-I03JsonFile -Path $readyPath `
            -TimeoutSeconds $PeerReadyTimeoutSeconds
        if ($null -eq $readyWait -or $readyWait.kind -ne 'value') {
            Stop-I03Fixture -Reason (
                "Peer did not publish peer-ready.json within " +
                "$PeerReadyTimeoutSeconds seconds"
            )
        }
        $peerReady = $readyWait.value
        Write-LabJson -Value $peerReady `
            -Path (Join-Path $evidence 'peer-ready.json') | Out-Null
        $peerReadyExact =
            [string]$peerReady.schema -eq
                'ese.v91.i03-peer-ready/v1' -and
            [string]$peerReady.case_id -eq $caseId -and
            [string]$peerReady.run_nonce -eq $nonce -and
            [bool]$peerReady.lab_account.
                disposable_account_acknowledged -and
            [bool]$peerReady.lab_account.expected_sid_binding_exact -and
            [string]$peerReady.lab_account.current_user_sid_sha256 -match
                '^[0-9a-f]{64}$' -and
            [string]$peerReady.peer.machine_id_sha256 -match
                '^[0-9a-f]{64}$' -and
            [string]$peerReady.peer.machine_identity.schema -eq
                'ese.v91.i03-machine-identity/v1' -and
            [bool]$peerReady.peer.machine_identity.collector_ok -and
            [string]$peerReady.peer.machine_identity.
                collector_error_code -eq 'NONE' -and
            [string]$peerReady.peer.machine_identity.source -eq
                'HKLM_MACHINEGUID_AND_WIN32_COMPUTERSYSTEM' -and
            [string]$peerReady.peer.machine_identity.
                machine_id_sha256 -eq
                    [string]$peerReady.peer.machine_id_sha256 -and
            -not [string]::IsNullOrWhiteSpace(
                [string]$peerReady.peer.machine_identity.manufacturer
            ) -and
            -not [string]::IsNullOrWhiteSpace(
                [string]$peerReady.peer.machine_identity.model
            ) -and
            -not [bool]$peerReady.peer.machine_identity.
                virtual_signature_detected -and
            [bool]$peerReady.peer.machine_identity.physical_host_claim -and
            [string]$peerReady.candidate.commit -eq $candidate.commit -and
            [string]$peerReady.candidate.emule_sha256 -eq $expectedHash -and
            [string]$peerReady.candidate.ese_server_sha256 -eq
                $candidate.ese_server_sha256 -and
            [string]$peerReady.candidate.build_info_sha256 -eq
                $candidate.build_info_sha256 -and
            [string]$peerReady.candidate.zip_sha256 -eq
                $expectedZipHash -and
            [Int64]$peerReady.candidate.zip_bytes -eq
                [Int64]$packageZipBindingBefore.zip_bytes -and
            [string]$peerReady.candidate.
                extracted_package_manifest_sha256 -eq
                    $packageIdentityBefore.manifest_sha256 -and
            [int]$peerReady.candidate.extracted_package_file_count -eq
                [int]$packageIdentityBefore.file_count -and
            [Int64]$peerReady.candidate.extracted_package_total_bytes -eq
                [Int64]$packageIdentityBefore.total_bytes -and
            [string]$peerReady.endpoint.public_ipv4 -eq $peerV4Text -and
            [string]$peerReady.endpoint.local_ipv4 -eq
                $peerLocalV4Text -and
            [string]$peerReady.endpoint.public_ipv6 -eq $peerV6Text -and
            [string]$peerReady.endpoint.expected_public_ipv6 -eq
                $peerV6Text -and
            [string]$peerReady.endpoint.ipv6_bind_preference -eq '::' -and
            [int]$peerReady.endpoint.tcp_port -eq $PeerTcpPort -and
            [bool]$peerReady.endpoint.dual_stack_listener -and
            [int]$peerReady.process.id -gt 0 -and
            [string]$peerReady.process.executable_sha256 -eq
                $expectedHash -and
            -not [bool]$peerReady.process.headless -and
            [string]$peerReady.process.stable_userhash_sha256 -match
                '^[0-9a-f]{64}$' -and
            [string]$peerReady.process.identity_profile.
                identity_bootstrap -eq 'fresh isolated profile' -and
            [bool]$peerReady.process.identity_profile.
                preferences_dat_absent_before_start -and
            [bool]$peerReady.process.identity_profile.
                cryptkey_dat_absent_before_start -and
            [int]$peerReady.process.identity_profile.
                max_upload_kib_per_second -eq $peerUploadCapKiBps -and
            [bool]$peerReady.process.identity_profile.
                dynamic_upload_disabled -and
            [string]$peerReady.fixture.name -eq "v91-i03-$nonce.zip" -and
            [Int64]$peerReady.fixture.bytes -eq $FileSizeBytes -and
            [string]$peerReady.fixture.sha256 -match
                '^[0-9a-fA-F]{64}$' -and
            [bool]$peerReady.fixture.
                upload_compression_disabled_by_extension -and
            [int]$peerReady.fixture.peer_max_upload_kib_per_second -eq
                $peerUploadCapKiBps -and
            [string]$peerReady.ed2k.hash -match '^[0-9A-F]{32}$' -and
            -not [bool]$peerReady.ed2k.source_extensions_present -and
            [string]$peerReady.isolation.web_allowed_ips -eq
                '127.0.0.1' -and
            -not [bool]$peerReady.isolation.kad_enabled -and
            -not [bool]$peerReady.isolation.server_enabled -and
            -not [bool]$peerReady.isolation.netlab_enabled
        if (-not $peerReadyExact) {
            Stop-I03Fixture `
                -Reason 'Peer ready evidence does not identify the exact candidate/run'
        }
        $sourceIdentity =
            [string]$peerReady.process.stable_userhash_sha256
        $null = $profileIdentityHashes.Add($sourceIdentity)
        $currentPeerPid = [int]$peerReady.process.id
        $sameIPv4PhysicalPrefix = Test-I03SamePhysicalPrefix `
            -LeftAddress ([string]$localV4.address) `
            -LeftPrefixLength ([int]$localV4.prefix_length) `
            -RightAddress ([string]$peerReady.peer.local_ipv4.address) `
            -RightPrefixLength ([int]$peerReady.peer.local_ipv4.prefix_length)
        $sameIPv6PhysicalPrefix = Test-I03SamePhysicalPrefix `
            -LeftAddress ([string]$localV6.address) `
            -LeftPrefixLength ([int]$localV6.prefix_length) `
            -RightAddress ([string]$peerReady.peer.public_ipv6.address) `
            -RightPrefixLength ([int]$peerReady.peer.public_ipv6.prefix_length)
        $physicalSingleAdapter = $topologyLocalValid -and
            [bool]$peerReady.peer.same_adapter -and
            [bool]$peerReady.peer.local_ipv4.adapter.physical_nonvirtual -and
            [bool]$peerReady.peer.public_ipv6.adapter.physical_nonvirtual -and
            [int]$peerReady.peer.local_ipv4.interface_index -eq
                [int]$peerReady.peer.public_ipv6.interface_index
        $topologyDecision = Get-I03TopologyDecision `
            -DifferentMachineIdentities (
                [string]$peerReady.peer.machine_id_sha256 -ne $localMachineId
            ) `
            -SameIPv4PhysicalPrefix $sameIPv4PhysicalPrefix `
            -SameIPv6PhysicalPrefix $sameIPv6PhysicalPrefix `
            -IPv6OnLink ([string]$routeV6.next_hop_class -eq 'on-link') `
            -NativeIPv4 ([string]$routeV4.remote_class -eq
                'global-public-v4') `
            -NativeIPv6 (
                [string]$routeV6.source_class -eq 'global-native-v6' -and
                [string]$routeV6.remote_class -eq 'global-native-v6' -and
                [string]$peerReady.peer.public_ipv6.address_class -eq
                    'global-native-v6'
            ) `
            -PhysicalSingleAdapter $physicalSingleAdapter `
            -OverlayDetected (-not $physicalSingleAdapter) `
            -RoutedNativeIPv6 ([string]$routeV6.next_hop_class -in @(
                'linklocal-v6', 'global-native-v6'
            ))
        $topologyT1 = [bool]$topologyDecision.t1_proved
        $topologyT2 = [bool]$topologyDecision.t2_proved
        $topologyValid = [string]$topologyDecision.status -ceq 'PASS'
        $topologyClass = [string]$topologyDecision.topology_class
        if (-not $topologyValid) {
            Stop-I03Fixture -Code 'TOPOLOGY' -Reason (
                'T1/T2 requires two distinct physical Windows hosts with ' +
                'both families on one physical interface per host, plus an ' +
                'observed on-link prefix match (T1) or routed native IPv6 ' +
                'next hop (T2)'
            )
        }

        $baselineProbeV4 = Open-I03TcpProbe -Address $peerV4Address `
            -Port $PeerTcpPort
        $baselineProbeV6 = Open-I03TcpProbe -Address $peerV6Address `
            -Port $PeerTcpPort
        if (-not $baselineProbeV4.evidence.adapter.physical_nonvirtual -or
            -not $baselineProbeV6.evidence.adapter.physical_nonvirtual -or
            [string]$baselineProbeV4.evidence.local_address -ne
                [string]$routeV4.source_address -or
            [string]$baselineProbeV6.evidence.local_address -ne
                [string]$routeV6.source_address) {
            Stop-I03Fixture `
                -Reason (
                    'Baseline probes did not use the preflight-certified ' +
                    'physical T1/T2 routes'
                )
        }
        $clockT0 = [DateTime]::UtcNow
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i03-baseline-command/v1'
            case_id = $caseId
            run_nonce = $nonce
            candidate_commit = $candidate.commit
            candidate_emule_sha256 = $expectedHash
            expected_source_process_id = $currentPeerPid
            clock_t0_utc = $clockT0.ToString('o')
            probes = @(
                $baselineProbeV4.evidence,
                $baselineProbeV6.evidence
            )
        }) -Path $baselineCommandPath | Out-Null
        $baselineAckWait = Wait-I03JsonFile -Path $baselineAckPath `
            -StopPath $stopPath -TimeoutSeconds 30
        $clockT3 = [DateTime]::UtcNow
        if ($null -eq $baselineAckWait -or
            $baselineAckWait.kind -ne 'value') {
            Stop-I03Fixture -Reason 'Peer did not acknowledge dual-family baseline'
        }
        $baselineAck = $baselineAckWait.value
        Write-LabJson -Value $baselineAck `
            -Path (Join-Path $evidence 'peer-baseline-ack.json') | Out-Null
        $baselineAckExact =
            [string]$baselineAck.schema -eq
                'ese.v91.i03-peer-baseline-ack/v1' -and
            [string]$baselineAck.case_id -eq $caseId -and
            [string]$baselineAck.run_nonce -eq $nonce -and
            [string]$baselineAck.candidate_commit -eq
                $candidate.commit -and
            [string]$baselineAck.candidate_emule_sha256 -eq
                $expectedHash -and
            [int]$baselineAck.source_process_id -eq $currentPeerPid -and
            [string]$baselineAck.source_process_emule_sha256 -eq
                $expectedHash -and
            [string]$baselineAck.source_userhash_sha256 -eq
                $sourceIdentity -and
            @($baselineAck.inbound_connections).Count -eq 2 -and
            [bool]$baselineAck.dualstack_marker.dualstack_capability_armed -and
            [bool]$baselineAck.api.available -and
            [bool]$baselineAck.api.isolation_valid
        if (-not $baselineAckExact) {
            Stop-I03Fixture -Reason 'Peer baseline acknowledgement is not exact'
        }
        $baselineInboundV4 = @(
            $baselineAck.inbound_connections | Where-Object {
                [string]$_.local_address -eq $peerLocalV4Text -and
                [int]$_.local_port -eq $PeerTcpPort
            }
        )
        $baselineV4InverseExact = $baselineInboundV4.Count -eq 1 -and
            [string]$baselineInboundV4[0].remote_address -eq
                [string]$baselineProbeV4.evidence.local_address -and
            [int]$baselineInboundV4[0].remote_port -eq
                [int]$baselineProbeV4.evidence.local_port
        $baselineInboundV6 = @(
            $baselineAck.inbound_connections | Where-Object {
                [string]$_.local_address -eq $peerV6Text -and
                [int]$_.local_port -eq $PeerTcpPort -and
                [string]$_.remote_address -eq
                    [string]$baselineProbeV6.evidence.local_address -and
                [int]$_.remote_port -eq
                    [int]$baselineProbeV6.evidence.local_port
            }
        )
        if ($baselineInboundV4.Count -ne 1 -or
            $baselineInboundV6.Count -ne 1 -or
            ($peerV4Text -eq $peerLocalV4Text -and
                -not $baselineV4InverseExact)) {
            Stop-I03Fixture -Reason (
                'Baseline tuples do not correlate both hosts'
            )
        }
        $clockEvidence = Get-I03ClockEvidence `
            -T0CoordinatorSendUtc $clockT0.ToString('o') `
            -T0CoordinatorEchoUtc `
                ([string]$baselineAck.clock.t0_coordinator_send_utc) `
            -T1PeerReceiveUtc `
                ([string]$baselineAck.clock.t1_peer_receive_utc) `
            -T2PeerSendUtc `
                ([string]$baselineAck.clock.t2_peer_send_utc) `
            -T3CoordinatorReceiveUtc $clockT3.ToString('o')
        if (-not [bool]$clockEvidence.collector_ok) {
            Stop-I03Fixture -Code 'CLOCK' `
                -Reason 'Clock challenge was malformed or reversed'
        }
        if (-not [bool]$clockEvidence.certified_within_1000_ms) {
            Stop-I03Fixture -Code 'CLOCK' -Reason (
                'T1 clock difference could not be certified at <= 1 second'
            )
        }
        $baselineEvidence = [ordered]@{
            schema = 'ese.v91.i03-baseline/v1'
            captured_at_utc = Get-LabUtcTimestamp
            coordinator = @(
                $baselineProbeV4.evidence,
                $baselineProbeV6.evidence
            )
            peer_ack = $baselineAck
            ipv6_inverse_tuple_exact = $true
            ipv4_correlation = [ordered]@{
                nat_mapped = $peerV4Text -ne $peerLocalV4Text
                inverse_tuple_exact = $baselineV4InverseExact
                method = if ($peerV4Text -ne $peerLocalV4Text) {
                    'nonce barrier + unique peer PID/local endpoint; remote tuple may be NAT-translated'
                } else { 'exact inverse tuple' }
                peer_observed_remote_address =
                    $baselineInboundV4[0].remote_address
                peer_observed_remote_port =
                    $baselineInboundV4[0].remote_port
            }
            clock = $clockEvidence
        }
        Write-LabJson -Value $baselineEvidence `
            -Path (Join-Path $evidence 'baseline.json') | Out-Null

        $baselineV4Tuple = Get-I03TupleKey -Family 'IPv4' `
            -LocalAddress $baselineProbeV4.evidence.local_address `
            -LocalPort $baselineProbeV4.evidence.local_port `
            -RemoteAddress $baselineProbeV4.evidence.remote_address `
            -RemotePort $baselineProbeV4.evidence.remote_port
        $baselineV6Tuple = Get-I03TupleKey -Family 'IPv6' `
            -LocalAddress $baselineProbeV6.evidence.local_address `
            -LocalPort $baselineProbeV6.evidence.local_port `
            -RemoteAddress $baselineProbeV6.evidence.remote_address `
            -RemotePort $baselineProbeV6.evidence.remote_port
        $baselineProbeV4.client.Dispose()
        $baselineProbeV4 = $null
        $baselineProbeV6.client.Dispose()
        $baselineProbeV6 = $null
        if (-not (Wait-I03OwnedTupleGone -ProcessId $PID `
            -TupleKey $baselineV4Tuple) -or
            -not (Wait-I03OwnedTupleGone -ProcessId $PID `
                -TupleKey $baselineV6Tuple)) {
            Stop-I03Fixture `
                -Reason 'Baseline probes remained active before policy cases'
        }

        foreach ($policy in @(
            [pscustomobject][ordered]@{
                name = 'auto'
                mode = 1
                expected_family = 'IPv4'
                tcp = $AutoTcpPort
                udp = $AutoUdpPort
                web = $AutoWebPort
            },
            [pscustomobject][ordered]@{
                name = 'preferred'
                mode = 2
                expected_family = 'IPv6'
                tcp = $PreferredTcpPort
                udp = $PreferredUdpPort
                web = $PreferredWebPort
            }
        )) {
            $currentPolicyName = [string]$policy.name
            $currentFailurePhase = 'case_setup'
            $currentFixtureCertified = $false
            $caseStarted = [DateTime]::UtcNow
            $failureCountBefore = $productFailures.Count
            $caseRecord = [ordered]@{
                schema = 'ese.v91.i03-policy-case/v1'
                policy = $policy.name
                ipv6_mode = $policy.mode
                expected_family = $policy.expected_family
                started_at_utc = $caseStarted.ToString('o')
                finished_at_utc = $null
                fixture_valid = $false
                fixture_certified = $false
                product_match = $false
                client = $null
                controlled_server = $null
                literal_ipv4_source_link_validated = $false
                link_injection = $null
                dualstack_rearm = $null
                prewarm = $null
                backlog_before_restart = $null
                post_restart = $null
                peer_complete = $null
                cleanup = $null
                runtime_error = $null
            }
            $caseRecorded = $false
            $caseNode = ''
            $caseExe = ''
            $casePreferencesOracle = $null
            $caseNodeInitialBinding = $null
            $caseNodeTerminalBinding = $null
            $caseTemp = ''
            $caseServerStop = $null
            try {
                $offset = $policy.tcp - 4662
                if (($policy.udp - 4672) -ne $offset -or
                    ($policy.web - 4711) -ne $offset) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) ports do not share the standard " +
                        '4662/4672/4711 offset'
                    )
                }
                $serverEvidencePath = Join-Path $evidence `
                    "$($policy.name)-controlled-ed2k-server.json"
                try {
                    $activeServer = Start-I03ControlledEd2kServer `
                        -EvidencePath $serverEvidencePath `
                        -ListenAddress ([string]$routeV4.source_address) `
                        -ExpectedClientAddress `
                            ([string]$routeV4.source_address) `
                        -RunNonce $nonce -Policy $policy.name `
                        -ForbiddenPorts @(
                            @($allPorts) + @($controlledServerPorts)
                        )
                } catch {
                    Stop-I03Fixture -Code 'EXTERNAL_CONTAMINATION' `
                        -Reason 'No collision-free controlled-server port was available'
                }
                [void]$controlledServerPorts.Add([int]$activeServer.port)
                try {
                    $allServerTcpRows = @(
                        Get-NetTCPConnection -ErrorAction Stop
                    )
                } catch {
                    Stop-I03Fixture -Code 'COLLECTOR_UNAVAILABLE' `
                        -Reason 'Controlled server listener collector failed'
                }
                $serverListeners = @($allServerTcpRows | Where-Object {
                    [string]$_.State -eq 'Listen' -and
                    (Get-I03NormalizedIp -Address `
                        ([string]$_.LocalAddress)) -eq
                            [string]$routeV4.source_address -and
                    [int]$_.LocalPort -eq $activeServer.port -and
                    [int]$_.OwningProcess -eq $PID
                })
                if ($serverListeners.Count -ne 1) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) controlled server is not one " +
                        'coordinator-owned physical-IP listener'
                    )
                }

                $casePreferencesOracle =
                    New-I03PreparedPreferencesOracle `
                        -PackagePath $candidate.package_path `
                        -PackageIdentity $packageIdentityBefore `
                        -OracleRoot (Join-Path $evidence `
                            "prepared-preferences-oracle-$($policy.name)") `
                        -NodeRole B `
                        -RunId "v91-i03-$($policy.name)" `
                        -PortOffset $offset
                Write-LabJson -Value $casePreferencesOracle -Path (
                    Join-Path $evidence `
                        "$($policy.name)-prepared-preferences-oracle.json"
                ) | Out-Null
                if (-not [bool]$casePreferencesOracle.collector_ok) {
                    Stop-I03Fixture -Code 'COLLECTOR_UNAVAILABLE' `
                        -Reason "$($policy.name) preferences oracle failed"
                }
                if (-not [bool]$casePreferencesOracle.source_bound) {
                    Stop-I03Fixture -Code 'PACKAGE_BINDING' -Reason (
                        "$($policy.name) source preferences did not match " +
                        'the frozen package manifest'
                    )
                }
                & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole B `
                    -SourcePackage $candidate.package_path -OutputRoot $nodes `
                    -RunId "v91-i03-$($policy.name)" -PortOffset $offset
                $caseNode = Join-Path $nodes `
                    "v91-i03-$($policy.name)-b"
                $caseExe = Join-Path $caseNode 'emule.exe'
                $caseNodeInitialBinding = Test-I03PreparedNodeBinding `
                    -NodePath $caseNode `
                    -PackageIdentity $packageIdentityBefore -Phase Initial `
                    -ExpectedPreparedPreferencesSha256 `
                        $casePreferencesOracle.
                            expected_prepared_preferences_sha256 `
                    -ExpectedPreparedPreferencesBytes `
                        $casePreferencesOracle.
                            expected_prepared_preferences_bytes
                Write-LabJson -Value $caseNodeInitialBinding -Path (
                    Join-Path $evidence `
                        "$($policy.name)-prepared-node-binding-initial.json"
                ) | Out-Null
                if (-not [bool]$caseNodeInitialBinding.collector_ok) {
                    Stop-I03Fixture -Code 'COLLECTOR_UNAVAILABLE' `
                        -Reason "$($policy.name) node-binding collector failed"
                }
                if (-not [bool]$caseNodeInitialBinding.bound) {
                    Stop-I03Fixture -Code 'PACKAGE_BINDING' -Reason (
                        "$($policy.name) prepared node did not match the " +
                        'frozen package manifest'
                    )
                }
                $caseIncoming = New-LabDirectory `
                    -Path (Join-Path $caseNode 'I03Incoming')
                $caseTemp = New-LabDirectory `
                    -Path (Join-Path $caseNode 'I03Temp')
                $casePassword = "v91-i03-$($policy.name)"
                $clientIsolation = Set-I03IsolatedPreferences `
                    -NodePath $caseNode `
                    -IPv6Mode $policy.mode -IPv6BindAddress '::' `
                    -WebPort $policy.web -Password $casePassword `
                    -IncomingPath $caseIncoming -TempPath $caseTemp

                try {
                    Wait-I03PortSetFree -Ports $allPorts
                } catch {
                    if ([string]$_.Exception.Message -match
                        '^I03_COLLECTOR::') {
                        Stop-I03Fixture -Code 'COLLECTOR_UNAVAILABLE' `
                            -Reason 'Reserved-port collector failed before certification'
                    }
                    Stop-I03Fixture -Code 'EXTERNAL_CONTAMINATION' `
                        -Reason 'A reserved candidate port was not free before certification'
                }

                # Package/topology/clock/peer/control-server prerequisites are
                # now exact. Candidate startup contradictions are product
                # evidence; collectors and control records remain lab gates.
                $currentFixtureCertified = $true
                $currentFailurePhase = 'identity_bootstrap'
                $caseRecord.fixture_certified = $true

                # preferences.dat is saved on graceful shutdown, not merely
                # on startup. Bootstrap a fresh identity while eD2K is still
                # disabled, then reopen that exact profile for the test.
                $activeClientExe = $caseExe
                try {
                    $activeClient = Start-Process -FilePath $caseExe `
                        -ArgumentList @(
                            '--portable', '--ignoreinstances',
                            "--metrics-port=$($policy.web)",
                            "--tcp-port=$($policy.tcp)",
                            "--udp-port=$($policy.udp)"
                        ) -WorkingDirectory $caseNode -PassThru `
                        -WindowStyle Hidden
                    $activeClientExpectedIdentity =
                        Get-I03ProcessIdentity -Process $activeClient
                    [void]$ownedCandidateProcessIds.Add(
                        [int]$activeClient.Id
                    )
                    $identityInitListener = Wait-I03Listener `
                        -Port $policy.tcp -Process $activeClient `
                        -RequireDualStack
                    $identityInitApi = Wait-I03Api -Port $policy.web `
                        -Process $activeClient
                } catch {
                    if ([string]$_.Exception.Message -match
                        '^I03_COLLECTOR::') {
                        Stop-I03Fixture -Code 'COLLECTOR_UNAVAILABLE' `
                            -Reason 'Identity bootstrap collector failed'
                    }
                    Stop-I03ProductFailure -Code 'CANDIDATE_EXITED' `
                        -SourceEvidence ([ordered]@{
                            process = $activeClientExpectedIdentity
                            phase = 'identity_bootstrap'
                        }) -Reason 'Candidate identity bootstrap did not start'
                }
                $identityInitUi =
                    Get-I03UiProbe -Process $activeClient
                if (-not $identityInitListener.dual_stack -or
                    (Get-LabSha256 -Path $activeClient.Path) -ne
                        $expectedHash) {
                    Stop-I03ProductFailure -Code 'CANDIDATE_EXITED' `
                        -SourceEvidence ([ordered]@{
                            process = $activeClientExpectedIdentity
                            listener = $identityInitListener
                        }) -Reason 'Candidate identity bootstrap listener was invalid'
                }
                if (-not (Test-I03ApiIsolation -Data $identityInitApi)) {
                    Stop-I03ProductFailure -Code 'API_CONTRACT' `
                        -SourceEvidence (Get-I03ApiEvidenceProjection `
                            -Data $identityInitApi -DurationMs 0) `
                        -Reason 'Candidate bootstrap API violated isolation'
                }
                if (-not $identityInitUi.main_window_present -or
                    -not $identityInitUi.message_pump_responsive) {
                    Stop-I03ProductFailure -Code 'UI_UNRESPONSIVE' `
                        -SourceEvidence $identityInitUi `
                        -Reason 'Candidate bootstrap UI was unresponsive'
                }
                $identityInitProcessId = $activeClient.Id
                $identityInitStop = Stop-I03OwnedProcess `
                    -Process $activeClient -ExpectedPath $activeClientExe `
                    -ExpectedIdentity $activeClientExpectedIdentity `
                    -RequireGraceful
                if (-not $identityInitStop.collector_ok) {
                    Stop-I03Fixture -Code 'COLLECTOR_UNAVAILABLE' `
                        -Reason 'Candidate bootstrap process collector failed'
                }
                if (-not $identityInitStop.stopped -or
                    -not $identityInitStop.graceful -or
                    $identityInitStop.unexpected_descendant_count -ne 0) {
                    Stop-I03ProductFailure -Code 'CANDIDATE_EXITED' `
                        -SourceEvidence $identityInitStop `
                        -Reason 'Candidate bootstrap did not stop gracefully'
                }
                $activeClient = $null
                try {
                    $clientIdentity =
                        Get-I03UserHashSha256 -NodePath $caseNode
                } catch {
                    Stop-I03ProductFailure -Code 'PEER_IDENTITY_CHANGED' `
                        -SourceEvidence ([ordered]@{
                            process_id = $identityInitProcessId
                            phase = 'identity_persistence'
                        }) -Reason 'Candidate identity was not persisted'
                }
                $identityUnique =
                    $profileIdentityHashes.Add($clientIdentity)
                if ($clientIdentity -notmatch '^[0-9a-f]{64}$' -or
                    -not $identityUnique -or
                    -not $clientIsolation.
                        preferences_dat_absent_before_start -or
                    -not $clientIsolation.
                        cryptkey_dat_absent_before_start) {
                    Stop-I03ProductFailure -Code 'PEER_IDENTITY_CHANGED' `
                        -SourceEvidence ([ordered]@{
                            identity_sha256 = $clientIdentity
                            unique = $identityUnique
                            profile = $clientIsolation
                        }) -Reason 'Candidate identity bootstrap invariant failed'
                }
                $controlProfile = Enable-I03ControlledEd2kProfile `
                    -NodePath $caseNode `
                    -ServerAddress ([string]$routeV4.source_address) `
                    -ServerPort $activeServer.port -RunNonce $nonce `
                    -Policy $policy.name -IPv6Mode $policy.mode `
                    -WebPort $policy.web
                $currentFailurePhase = 'candidate_startup'

                try {
                    Wait-I03PortSetFree -Ports $allPorts
                } catch {
                    if ([string]$_.Exception.Message -match
                        '^I03_COLLECTOR::') {
                        Stop-I03Fixture -Code 'COLLECTOR_UNAVAILABLE' `
                            -Reason 'Reserved-port collector failed before candidate startup'
                    }
                    Stop-I03Fixture -Code 'EXTERNAL_CONTAMINATION' `
                        -Reason 'A reserved candidate port was not free before startup'
                }

                # Normal mode is mandatory: it provides the UI liveness probe
                # and does not regenerate the userhash on startup.
                try {
                    $activeClient = Start-Process -FilePath $caseExe `
                        -ArgumentList @(
                            '--portable', '--ignoreinstances',
                            "--metrics-port=$($policy.web)",
                            "--tcp-port=$($policy.tcp)",
                            "--udp-port=$($policy.udp)"
                        ) -WorkingDirectory $caseNode -PassThru `
                        -WindowStyle Hidden
                    $activeClientExpectedIdentity =
                        Get-I03ProcessIdentity -Process $activeClient
                    $activeServer.state['expected_client_process_id'] =
                        [int]$activeClient.Id
                    [void]$ownedCandidateProcessIds.Add(
                        [int]$activeClient.Id
                    )
                    $activeClientExe = $caseExe
                    $clientListener = Wait-I03Listener -Port $policy.tcp `
                        -Process $activeClient -RequireDualStack
                    $null = Wait-I03Api -Port $policy.web `
                        -Process $activeClient
                    $serverLogin = Wait-I03ControlledEd2kLogin `
                        -Server $activeServer -Process $activeClient `
                        -ExpectedTcpPort $policy.tcp
                } catch {
                    $startupFailureMessage = [string]$_.Exception.Message
                    if ($startupFailureMessage -match
                        '^I03_COLLECTOR::') {
                        Stop-I03Fixture -Code 'COLLECTOR_UNAVAILABLE' `
                            -Reason 'Candidate startup collector failed'
                    }
                    if ($startupFailureMessage -eq
                        'I03_FIXTURE::CONTROLLED_ED2K_SERVER_FAILED') {
                        Stop-I03Fixture `
                            -Code 'HARNESS_EXCEPTION' `
                            -Reason 'Controlled eD2K fixture failed'
                    }
                    if ($startupFailureMessage -eq
                        'I03_FIXTURE::EXTERNAL_CONTAMINATION') {
                        Stop-I03Fixture -Code 'EXTERNAL_CONTAMINATION' `
                            -Reason 'Controlled eD2K endpoint was contaminated'
                    }
                    if ($startupFailureMessage -in @(
                        'I03_PRODUCT::CONTROLLED_ED2K_PROTOCOL',
                        'I03_PRODUCT::CONTROLLED_ED2K_TRANSPORT'
                    )) {
                        Stop-I03ProductFailure -Code 'API_CONTRACT' `
                            -SourceEvidence ([ordered]@{
                                process = $activeClientExpectedIdentity
                                controlled_server_error_kind =
                                    [string]$activeServer.state['error_kind']
                                controlled_server_error_code =
                                    [string]$activeServer.state['error_code']
                            }) -Reason 'Candidate emitted an invalid eD2K login frame'
                    }
                    $activeExited = $false
                    if ($null -ne $activeClient) {
                        try {
                            $activeClient.Refresh()
                            $activeExited = [bool]$activeClient.HasExited
                        } catch { $activeExited = $true }
                    }
                    $startupCode = if ($activeExited -or
                        $null -eq $activeClient) {
                        'CANDIDATE_EXITED'
                    } else { 'API_UNAVAILABLE' }
                    Stop-I03ProductFailure -Code $startupCode `
                        -SourceEvidence ([ordered]@{
                            process = $activeClientExpectedIdentity
                            exited = $activeExited
                            phase = 'candidate_startup'
                        }) -Reason 'Candidate controlled startup failed'
                }
                $apiDeadline = [DateTime]::UtcNow.AddSeconds(60)
                $clientApi = $null
                do {
                    $clientApi = Get-I03ApiProbe -Port $policy.web `
                        -AllowControlledEd2k
                    if ($clientApi.available -and
                        $clientApi.isolation_valid) {
                        break
                    }
                    Start-Sleep -Milliseconds 200
                } while ([DateTime]::UtcNow -lt $apiDeadline)
                $clientUi = Get-I03UiProbe -Process $activeClient
                try {
                    $runtimeClientIdentity =
                        Get-I03UserHashSha256 -NodePath $caseNode
                } catch {
                    Stop-I03ProductFailure -Code 'PEER_IDENTITY_CHANGED' `
                        -SourceEvidence ([ordered]@{
                            process = $activeClientExpectedIdentity
                            phase = 'controlled_startup_identity'
                        }) -Reason 'Candidate persisted identity became unreadable'
                }
                if ($runtimeClientIdentity -ne $clientIdentity) {
                    Stop-I03ProductFailure -Code 'PEER_IDENTITY_CHANGED' `
                        -SourceEvidence ([ordered]@{
                            process = $activeClientExpectedIdentity
                            expected_identity_sha256 = $clientIdentity
                            actual_identity_sha256 = $runtimeClientIdentity
                        }) -Reason 'Candidate identity changed at controlled startup'
                }
                $startupCensus = Get-I03ProcessSocketCensus `
                    -ProcessId $activeClient.Id
                if (-not [bool]$startupCensus.collector_ok) {
                    Stop-I03Fixture -Code 'COLLECTOR_UNAVAILABLE' `
                        -Reason 'Candidate startup socket census failed'
                }
                $startupSocketDecision =
                    Get-I03CandidateSocketCensusDecision `
                        -Census $startupCensus `
                        -ProcessId $activeClient.Id `
                        -TcpPort $policy.tcp -UdpPort $policy.udp `
                        -WebPort $policy.web `
                        -TargetAddresses @($peerV4Text, $peerV6Text) `
                        -TargetPort $PeerTcpPort `
                        -ControlAddress ([string]$routeV4.source_address) `
                        -ControlPort $activeServer.port
                Write-LabJson -Value ([ordered]@{
                    census = $startupCensus
                    decision = $startupSocketDecision
                }) -Path (Join-Path $evidence `
                    "$($policy.name)-startup-socket-census.json") | Out-Null
                $serverConnections = @($startupCensus.tcp_rows |
                    Where-Object {
                        [string]$_.state -eq 'Established' -and
                        (Get-I03NormalizedIp -Address `
                            ([string]$_.remote_address)) -eq
                                [string]$routeV4.source_address -and
                        [int]$_.remote_port -eq $activeServer.port
                    })
                $startupConnections = @($startupCensus.tcp_rows |
                    Where-Object { [string]$_.state -eq 'Established' })
                $unexpectedStartupConnections = @(
                    $startupSocketDecision.unexpected_rows
                )
                if (-not $clientListener.dual_stack -or
                    (Get-LabSha256 -Path $activeClient.Path) -ne
                        $expectedHash -or
                    $serverConnections.Count -ne 1 -or
                    -not $serverLogin.endpoint_is_same_host_physical) {
                    Stop-I03ProductFailure -Code 'CANDIDATE_EXITED' `
                        -SourceEvidence ([ordered]@{
                            process = $activeClientExpectedIdentity
                            listener = $clientListener
                            server_login = $serverLogin
                            control_connection_count = $serverConnections.Count
                        }) -Reason 'Candidate control-plane startup invariant failed'
                }
                if (-not $clientApi.available) {
                    Stop-I03ProductFailure -Code 'API_UNAVAILABLE' `
                        -SourceEvidence $clientApi `
                        -Reason 'Candidate API unavailable after controlled startup'
                }
                if (-not $clientApi.isolation_valid) {
                    Stop-I03ProductFailure -Code 'API_CONTRACT' `
                        -SourceEvidence $clientApi `
                        -Reason 'Candidate API violated isolation contract'
                }
                if (-not $clientUi.main_window_present -or
                    -not $clientUi.message_pump_responsive) {
                    Stop-I03ProductFailure -Code 'UI_UNRESPONSIVE' `
                        -SourceEvidence $clientUi `
                        -Reason 'Candidate UI was unresponsive at startup'
                }
                if ($unexpectedStartupConnections.Count -ne 0) {
                    Stop-I03ProductFailure `
                        -Code 'CANDIDATE_THIRD_PARTY_SOCKET' `
                        -SourceEvidence $unexpectedStartupConnections `
                        -Reason 'Candidate opened an unexpected startup connection'
                }
                $clientStartup = [ordered]@{
                    process_id = $activeClient.Id
                    executable_sha256 = Get-LabSha256 `
                        -Path $activeClient.Path
                    source_mode = 'non-headless'
                    ports = [ordered]@{
                        tcp = $policy.tcp
                        udp = $policy.udp
                        web = $policy.web
                    }
                    ipv6_mode = $policy.mode
                    ipv6_bind = '::'
                    dual_stack_listener = $clientListener.dual_stack
                    identity = [ordered]@{
                        initialized_userhash_sha256 = $clientIdentity
                        runtime_userhash_sha256 =
                            $runtimeClientIdentity
                        preserved_across_controlled_startup =
                            $runtimeClientIdentity -eq $clientIdentity
                        source_userhash_sha256 = $sourceIdentity
                        distinct_from_source =
                            $clientIdentity -ne $sourceIdentity
                        distinct_from_all_prior_profiles =
                            $identityUnique
                        initialization = [ordered]@{
                            process_id = $identityInitProcessId
                            source_mode = 'non-headless'
                            ed2k_connected = $false
                            dual_stack_listener =
                                $identityInitListener.dual_stack
                            api_isolation_valid =
                                Test-I03ApiIsolation `
                                    -Data $identityInitApi
                            ui = $identityInitUi
                            graceful_stop =
                                $identityInitStop.graceful
                        }
                        profile = $clientIsolation
                    }
                    api = $clientApi
                    ui = $clientUi
                    profile = $controlProfile
                    web_allowed_ips = '127.0.0.1'
                    isolation_controls = [ordered]@{
                        update_notify = $false
                        serverlist_auto_update = $false
                        add_servers_from_server = $false
                        add_servers_from_client = $false
                        kad = $false
                        netlab = $false
                        proxy = $false
                        literal_control_server_address = $true
                    }
                    controlled_server_login = $serverLogin
                    startup_established_connections = @(
                        $startupConnections | ForEach-Object {
                            [pscustomobject][ordered]@{
                                local_address =
                                    Get-I03NormalizedIp -Address `
                                        ([string]$_.local_address)
                                local_port = [int]$_.local_port
                                remote_address =
                                    Get-I03NormalizedIp -Address `
                                        ([string]$_.remote_address)
                                remote_port = [int]$_.remote_port
                                owning_process = [int]$_.owning_process
                            }
                        }
                    )
                    unexpected_startup_connection_count =
                        $unexpectedStartupConnections.Count
                }
                $caseRecord.client = $clientStartup
                $caseRecord.controlled_server = [ordered]@{
                    listen_address = $routeV4.source_address
                    listen_port = $activeServer.port
                    listener_owning_process = $PID
                    listener_exact = $serverListeners.Count -eq 1
                    login = $serverLogin
                    third_party = $false
                    dns_used = $false
                }
                Write-LabJson -Value $clientStartup -Path (
                    Join-Path $evidence `
                        "$($policy.name)-client-startup.json"
                ) | Out-Null

                # Arm the CURRENT peer process. Keep the native-v6 TcpClient
                # open until the peer proves the exact inverse tuple and a
                # one-marker delta for this PID.
                $rearmProbe = Open-I03TcpProbe -Address $peerV6Address `
                    -Port $PeerTcpPort
                $rearmTuple = Get-I03TupleKey -Family 'IPv6' `
                    -LocalAddress $rearmProbe.evidence.local_address `
                    -LocalPort $rearmProbe.evidence.local_port `
                    -RemoteAddress $rearmProbe.evidence.remote_address `
                    -RemotePort $rearmProbe.evidence.remote_port
                $rearmPath = Join-Path $coordination `
                    "$($policy.name)-rearm.json"
                $rearmAckPath = Join-Path $coordination `
                    "peer-$($policy.name)-rearm-ack.json"
                $rearmAck = $null
                try {
                    Write-LabJson -Value ([ordered]@{
                        schema = 'ese.v91.i03-rearm-command/v1'
                        case_id = $caseId
                        run_nonce = $nonce
                        policy = $policy.name
                        ipv6_mode = $policy.mode
                        candidate_commit = $candidate.commit
                        candidate_emule_sha256 = $expectedHash
                        expected_source_process_id = $currentPeerPid
                        coordinator_local_ipv6 =
                            $rearmProbe.evidence.local_address
                        coordinator_local_port =
                            $rearmProbe.evidence.local_port
                        peer_ipv6 = $peerV6Text
                        peer_tcp_port = $PeerTcpPort
                    }) -Path $rearmPath | Out-Null
                    $rearmAckWait = Wait-I03JsonFile `
                        -Path $rearmAckPath -StopPath $stopPath `
                        -TimeoutSeconds 30
                    if ($null -eq $rearmAckWait -or
                        $rearmAckWait.kind -ne 'value') {
                        Stop-I03Fixture -Reason (
                            "Peer did not acknowledge $($policy.name) " +
                            'current-PID DUALSTACK rearm'
                        )
                    }
                    $rearmAck = $rearmAckWait.value
                    Write-LabJson -Value $rearmAck -Path (
                        Join-Path $evidence `
                            "$($policy.name)-peer-rearm-ack.json"
                    ) | Out-Null
                    $rearmExact =
                        [string]$rearmAck.schema -eq
                            'ese.v91.i03-peer-rearm-ack/v1' -and
                        [string]$rearmAck.case_id -eq $caseId -and
                        [string]$rearmAck.run_nonce -eq $nonce -and
                        [string]$rearmAck.policy -eq $policy.name -and
                        [int]$rearmAck.ipv6_mode -eq $policy.mode -and
                        [string]$rearmAck.candidate_commit -eq
                            $candidate.commit -and
                        [string]$rearmAck.candidate_emule_sha256 -eq
                            $expectedHash -and
                        [int]$rearmAck.source_process_id -eq
                            $currentPeerPid -and
                        [string]$rearmAck.source_process_emule_sha256 -eq
                            $expectedHash -and
                        [string]$rearmAck.source_userhash_sha256 -eq
                            $sourceIdentity -and
                        [bool]$rearmAck.runtime_dualstack_rearmed -and
                        [int]$rearmAck.inbound_marker_delta -eq 1 -and
                        [int]$rearmAck.accepted_marker_delta -eq 1 -and
                        [string]$rearmAck.inbound_connection.local_address -eq
                            $peerV6Text -and
                        [int]$rearmAck.inbound_connection.local_port -eq
                            $PeerTcpPort -and
                        [string]$rearmAck.inbound_connection.remote_address -eq
                            [string]$rearmProbe.evidence.local_address -and
                        [int]$rearmAck.inbound_connection.remote_port -eq
                            [int]$rearmProbe.evidence.local_port
                    if (-not $rearmExact) {
                        Stop-I03Fixture -Reason (
                            "$($policy.name) DUALSTACK rearm evidence " +
                            'is not current-PID/exact'
                        )
                    }
                } finally {
                    $rearmProbe.client.Dispose()
                }
                if (-not (Wait-I03OwnedTupleGone -ProcessId $PID `
                    -TupleKey $rearmTuple)) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) rearm probe remained active " +
                        'before prewarm'
                    )
                }
                $caseRecord.dualstack_rearm = [ordered]@{
                    coordinator = $rearmProbe.evidence
                    peer = $rearmAck
                    exact_inverse_tuple = $true
                    current_source_process_id = $currentPeerPid
                }

                $directLink = [string]$peerReady.ed2k.base_link +
                    "|sources,$peerV4Text`:$PeerTcpPort|/"
                if ($directLink -notmatch (
                    '\|sources,' + [regex]::Escape($peerV4Text) + ':' +
                    $PeerTcpPort + '\|/$'
                ) -or $directLink -match
                    ('(?i)\|sources,\[' +
                        [regex]::Escape($peerV6Text))) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) direct source link is not " +
                        'literal-IPv4-only'
                    )
                }
                $caseRecord.literal_ipv4_source_link_validated = $true
                $currentFixtureCertified = $true
                $currentFailurePhase = 'link_injection'
                $caseRecord.fixture_certified = $true
                $linkDeliveries =
                    [System.Collections.Generic.List[object]]::new()
                try {
                    $linkDeliveries.Add(
                        (Send-I03Ed2kLink -Process $activeClient `
                            -Link $directLink)
                    )
                    Start-Sleep -Seconds 2
                    $linkDeliveries.Add(
                        (Send-I03Ed2kLink -Process $activeClient `
                            -Link $directLink)
                    )
                } catch {
                    $activeClient.Refresh()
                    $linkCode = if ($activeClient.HasExited) {
                        'CANDIDATE_EXITED'
                    } else { 'LINK_REJECTED' }
                    Stop-I03ProductFailure -Code $linkCode `
                        -SourceEvidence ([ordered]@{
                            process = $activeClientExpectedIdentity
                            exited = [bool]$activeClient.HasExited
                            completed_deliveries = $linkDeliveries.Count
                        }) -Reason (
                        "$($policy.name) candidate did not accept the " +
                        "bounded eD2K-link injection: " +
                        "$($_.Exception.Message); exited=" +
                        [string]$activeClient.HasExited
                    )
                }
                $caseRecord.link_injection = [ordered]@{
                    bounded = $true
                    attempts = @($linkDeliveries)
                    all_accepted = $linkDeliveries.Count -eq 2 -and
                        @($linkDeliveries | Where-Object {
                            -not [bool]$_.delivered -or
                            -not [bool]$_.accepted
                        }).Count -eq 0
                }
                $prewarmSamples = Join-Path $evidence `
                    "$($policy.name)-prewarm-samples.jsonl"
                $currentFailurePhase = 'ipv4_prewarm'
                try {
                    $prewarm = Wait-I03Prewarm -Process $activeClient `
                        -ControlledServer $activeServer `
                        -NodePath $caseNode -TempPath $caseTemp `
                        -WebPort $policy.web -TcpPort $policy.tcp `
                        -UdpPort $policy.udp `
                        -TargetAddresses @($peerV4Text, $peerV6Text) `
                        -TargetPort $PeerTcpPort `
                        -ControlAddress ([string]$routeV4.source_address) `
                        -ControlPort $activeServer.port `
                        -TimeoutSeconds $CaseTimeoutSeconds `
                        -SamplesPath $prewarmSamples
                } catch {
                    $prewarmFailureMessage = [string]$_.Exception.Message
                    if ($prewarmFailureMessage -match
                        '^I03_COLLECTOR::') {
                        Stop-I03Fixture -Code 'COLLECTOR_UNAVAILABLE' `
                            -Reason 'IPv4 prewarm socket collector failed'
                    }
                    if ($prewarmFailureMessage -in @(
                        'I03_PRODUCT::CONTROLLED_ED2K_PROTOCOL',
                        'I03_PRODUCT::CONTROLLED_ED2K_TRANSPORT'
                    )) {
                        Stop-I03ProductFailure -Code 'API_CONTRACT' `
                            -SourceEvidence ([ordered]@{
                                process = $activeClientExpectedIdentity
                                error_kind =
                                    [string]$activeServer.state['error_kind']
                                error_code =
                                    [string]$activeServer.state['error_code']
                            }) -Reason 'Candidate violated controlled eD2K transport'
                    }
                    if ($prewarmFailureMessage -eq
                        'I03_FIXTURE::EXTERNAL_CONTAMINATION') {
                        Stop-I03Fixture -Code 'EXTERNAL_CONTAMINATION' `
                            -Reason 'Controlled eD2K endpoint was contaminated'
                    }
                    if ($prewarmFailureMessage -eq
                        'I03_FIXTURE::CONTROLLED_ED2K_SERVER_FAILED') {
                        Stop-I03Fixture -Code 'HARNESS_EXCEPTION' `
                            -Reason 'Controlled eD2K fixture failed during prewarm'
                    }
                    if ($_.Exception.Message -match
                        'Client exited|Ambiguous or non-IPv4 connection') {
                        $prewarmCode = if ($_.Exception.Message -match
                            'Client exited') {
                            'CANDIDATE_EXITED'
                        } else { 'IPV4_PREWARM_INVARIANT' }
                        Stop-I03ProductFailure -Code $prewarmCode `
                            -SourceEvidence ([ordered]@{
                                process = $activeClientExpectedIdentity
                                phase = 'ipv4_prewarm'
                            }) -Reason (
                            "$($policy.name) candidate failed during " +
                            "IPv4 prewarm: $($_.Exception.Message)"
                        )
                    }
                    throw
                }
                if ([int]$prewarm.other_pid_connection_count -ne 0) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) IPv4 prewarm was contaminated " +
                        'by another local process'
                    )
                }
                if ([int]$prewarm.
                    unexpected_socket_observation_count -gt 0) {
                    Stop-I03ProductFailure `
                        -Code 'CANDIDATE_THIRD_PARTY_SOCKET' `
                        -SourceEvidence $prewarm `
                        -Reason 'Candidate opened a non-allowlisted prewarm socket'
                }
                if ([int]$prewarm.
                    duplicate_target_observation_count -gt 0) {
                    Stop-I03ProductFailure `
                        -Code 'IPV4_PREWARM_INVARIANT' `
                        -SourceEvidence $prewarm `
                        -Reason 'Candidate opened concurrent active target sockets during prewarm'
                }
                $helloDecision = Get-I03HelloEvidenceDecision `
                    -Evidence $prewarm.hello
                if ([string]$helloDecision.status -ceq
                    'PRODUCT_INVARIANT') {
                    Stop-I03ProductFailure `
                        -Code ([string]$helloDecision.code) `
                        -SourceEvidence $prewarm.hello `
                        -Reason 'Candidate produced no HELLO log on a certified prewarm fixture'
                }
                if ([string]$helloDecision.status -ceq 'LAB_BLOCKED') {
                    Stop-I03Fixture -Code ([string]$helloDecision.code) `
                        -Reason 'HELLO log enumeration or read collector failed'
                }
                if ($null -eq $prewarm.socket -or
                    -not [bool]$prewarm.socket.collector_ok) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) socket collector was unavailable " +
                        'or ambiguous during prewarm'
                    )
                }
                $prewarmExact =
                    [bool]$prewarm.complete -and
                    $null -ne $prewarm.selected_connection -and
                    [string]$prewarm.selected_connection.family -eq
                        'IPv4' -and
                    [string]$prewarm.selected_connection.remote_address -eq
                        $peerV4Text -and
                    [int]$prewarm.selected_connection.remote_port -eq
                        $PeerTcpPort -and
                    [int]$prewarm.selected_connection.owning_process -eq
                        $activeClient.Id -and
                    [string]$prewarm.selected_connection.local_address -eq
                        [string]$routeV4.source_address -and
                    [bool]$prewarm.socket.pid_matches -and
                    [bool]$prewarm.socket.tuple_current_exact -and
                    [bool]$prewarm.socket.local_address_assigned -and
                    [bool]$prewarm.socket.physical_nonvirtual -and
                    [bool]$prewarm.transfer_progress -and
                    [bool]$prewarm.hello.learned_public_ipv6_via_hello -and
                    [int]$prewarm.hello.highid_hello_answer_count -gt 0 -and
                    [int]$prewarm.hello.lowid_like_hello_answer_count -eq 0 -and
                    [bool]$prewarm.health_valid
                if (-not $prewarmExact) {
                    Stop-I03ProductFailure `
                        -Code 'IPV4_PREWARM_INVARIANT' `
                        -SourceEvidence $prewarm -Reason (
                        "$($policy.name) candidate did not establish the " +
                        'IPv4 HighID HELLO/transfer prewarm on the valid ' +
                        'controlled fixture'
                    )
                }
                Write-LabJson -Value $prewarm -Path (
                    Join-Path $evidence "$($policy.name)-prewarm.json"
                ) | Out-Null
                $caseRecord.prewarm = $prewarm

                $prewarmPath = Join-Path $coordination `
                    "$($policy.name)-prewarm.json"
                $prewarmAckPath = Join-Path $coordination `
                    "peer-$($policy.name)-prewarm-ack.json"
                Write-LabJson -Value ([ordered]@{
                    schema = 'ese.v91.i03-prewarm-command/v1'
                    case_id = $caseId
                    run_nonce = $nonce
                    policy = $policy.name
                    ipv6_mode = $policy.mode
                    expected_family = $policy.expected_family
                    candidate_commit = $candidate.commit
                    candidate_emule_sha256 = $expectedHash
                    expected_source_process_id = $currentPeerPid
                    client_process_id = $activeClient.Id
                    client_tuple = $prewarm.selected_connection
                }) -Path $prewarmPath | Out-Null
                $prewarmAckWait = Wait-I03JsonFile `
                    -Path $prewarmAckPath -StopPath $stopPath `
                    -TimeoutSeconds 30
                if ($null -eq $prewarmAckWait -or
                    $prewarmAckWait.kind -ne 'value') {
                    Stop-I03Fixture -Reason (
                        "Peer did not acknowledge $($policy.name) prewarm"
                    )
                }
                $prewarmAck = $prewarmAckWait.value
                Write-LabJson -Value $prewarmAck -Path (
                    Join-Path $evidence `
                        "$($policy.name)-peer-prewarm-ack.json"
                ) | Out-Null
                $prewarmV4InverseExact =
                    [string]$prewarmAck.inbound_connection.remote_address -eq
                        [string]$prewarm.selected_connection.local_address -and
                    [int]$prewarmAck.inbound_connection.remote_port -eq
                        [int]$prewarm.selected_connection.local_port
                $prewarmAckExact =
                    [string]$prewarmAck.schema -eq
                        'ese.v91.i03-peer-prewarm-ack/v1' -and
                    [string]$prewarmAck.case_id -eq $caseId -and
                    [string]$prewarmAck.run_nonce -eq $nonce -and
                    [string]$prewarmAck.policy -eq $policy.name -and
                    [int]$prewarmAck.ipv6_mode -eq $policy.mode -and
                    [string]$prewarmAck.candidate_commit -eq
                        $candidate.commit -and
                    [string]$prewarmAck.candidate_emule_sha256 -eq
                        $expectedHash -and
                    [int]$prewarmAck.source_process_id -eq
                        $currentPeerPid -and
                    [string]$prewarmAck.source_process_emule_sha256 -eq
                        $expectedHash -and
                    [string]$prewarmAck.source_userhash_sha256 -eq
                        $sourceIdentity -and
                    [int]$prewarmAck.client_process_id_from_command -eq
                        $activeClient.Id -and
                    [string]$prewarmAck.inbound_connection.local_address -eq
                        $peerLocalV4Text -and
                    [int]$prewarmAck.inbound_connection.local_port -eq
                        $PeerTcpPort -and
                    ($peerV4Text -ne $peerLocalV4Text -or
                        $prewarmV4InverseExact) -and
                    [bool]$prewarmAck.api.available -and
                    [bool]$prewarmAck.api.isolation_valid
                if (-not $prewarmAckExact) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) prewarm tuple/peer ack " +
                        'is not exact'
                    )
                }
                $prewarm | Add-Member -NotePropertyName `
                    peer_ipv4_correlation -NotePropertyValue `
                    ([pscustomobject][ordered]@{
                        nat_mapped =
                            $peerV4Text -ne $peerLocalV4Text
                        inverse_tuple_exact = $prewarmV4InverseExact
                        peer_observed_remote_address =
                            $prewarmAck.inbound_connection.remote_address
                        peer_observed_remote_port =
                            $prewarmAck.inbound_connection.remote_port
                    }) -Force
                Write-LabJson -Value $prewarm -Path (
                    Join-Path $evidence "$($policy.name)-prewarm.json"
                ) | Out-Null

                # A completed download has no reason to redial after the peer
                # restart. Prove a large backlog while the exact IPv4 prewarm
                # tuple is still live, before issuing the restart barrier.
                $backlogCapturedAt = [DateTime]::UtcNow
                $caseElapsedSeconds =
                    ($backlogCapturedAt - $caseStarted).TotalSeconds
                $configuredTransferUpperBytes = [Int64][Math]::Ceiling(
                    $peerUploadCapKiBps * 1024.0 *
                        [Math]::Max(0.0, $caseElapsedSeconds) +
                    16MB
                )
                $minimumBacklogBytes = [Int64]$FileSizeBytes -
                    $configuredTransferUpperBytes
                try {
                    $partFiles = @(Get-ChildItem -LiteralPath $caseTemp `
                        -File -Filter '*.part' -ErrorAction Stop)
                    $partMetFiles = @(Get-ChildItem -LiteralPath $caseTemp `
                        -File -Filter '*.part.met' -ErrorAction Stop)
                } catch {
                    Stop-I03Fixture -Code 'COLLECTOR_UNAVAILABLE' `
                        -Reason 'Backlog temp-file collector failed'
                }
                $completedFixturePath = Join-Path $caseIncoming `
                    ([string]$peerReady.fixture.name)
                try {
                    $currentPrewarmMatches = @(
                        Get-I03TargetConnections | Where-Object {
                            [int]$_.owning_process -eq $activeClient.Id -and
                            [string]$_.state -eq 'Established' -and
                            [string]$_.tuple_key -eq
                                [string]$prewarm.selected_connection.tuple_key
                        }
                    )
                } catch {
                    Stop-I03Fixture -Code 'COLLECTOR_UNAVAILABLE' `
                        -Reason 'Backlog TCP collector was unavailable'
                }
                $currentFailurePhase = 'backlog_revalidation'
                if ($currentPrewarmMatches.Count -eq 0) {
                    Stop-I03ProductFailure -Code 'NO_ROUTE' `
                        -SourceEvidence ([ordered]@{
                            prewarm_tuple_sha256 = Get-LabStringSha256 `
                                -Value ([string]$prewarm.
                                    selected_connection.tuple_key)
                            current_match_count = 0
                        }) -Reason 'Certified IPv4 prewarm route disappeared before restart'
                }
                if ($currentPrewarmMatches.Count -gt 1) {
                    Stop-I03ProductFailure -Code 'DUPLICATE_ROUTE' `
                        -SourceEvidence $currentPrewarmMatches `
                        -Reason 'Certified prewarm tuple became duplicate before restart'
                }
                $currentPrewarmSocket = if (
                    $currentPrewarmMatches.Count -eq 1
                ) {
                    Get-I03SocketEvidence `
                        -Connection $currentPrewarmMatches[0] `
                        -ExpectedProcessId $activeClient.Id
                } else { $null }
                if ($null -eq $currentPrewarmSocket -or
                    -not [bool]$currentPrewarmSocket.collector_ok) {
                    Stop-I03Fixture -Code 'COLLECTOR_AMBIGUOUS' -Reason (
                        "$($policy.name) contemporaneous backlog socket " +
                        'collector was unavailable or ambiguous'
                    )
                }
                $backlogValid =
                    [IO.Path]::GetExtension(
                        [string]$peerReady.fixture.name
                    ).ToLowerInvariant() -eq '.zip' -and
                    [bool]$peerReady.fixture.
                        upload_compression_disabled_by_extension -and
                    [int]$peerReady.fixture.
                        peer_max_upload_kib_per_second -eq
                            $peerUploadCapKiBps -and
                    $partFiles.Count -eq 1 -and
                    $partMetFiles.Count -ge 1 -and
                    -not (Test-Path -LiteralPath $completedFixturePath `
                        -PathType Leaf) -and
                    $minimumBacklogBytes -ge 64MB -and
                    $currentPrewarmMatches.Count -eq 1 -and
                    [bool]$currentPrewarmSocket.tuple_current_exact -and
                    [bool]$currentPrewarmSocket.physical_nonvirtual
                $backlogEvidence = [ordered]@{
                    schema = 'ese.v91.i03-backlog-before-restart/v1'
                    policy = $policy.name
                    captured_at_utc = $backlogCapturedAt.ToString('o')
                    fixture_name = $peerReady.fixture.name
                    fixture_bytes = [Int64]$FileSizeBytes
                    compression_disabled_extension = '.zip'
                    peer_max_upload_kib_per_second =
                        $peerUploadCapKiBps
                    case_elapsed_seconds =
                        [Math]::Round($caseElapsedSeconds, 3)
                    startup_burst_allowance_bytes = 16MB
                    configured_transfer_upper_bound_bytes =
                        $configuredTransferUpperBytes
                    minimum_backlog_bytes = $minimumBacklogBytes
                    part_file_count = $partFiles.Count
                    part_met_file_count = $partMetFiles.Count
                    part_files = @($partFiles | ForEach-Object {
                        [pscustomobject][ordered]@{
                            name = $_.Name
                            bytes = [Int64]$_.Length
                            last_write_utc =
                                $_.LastWriteTimeUtc.ToString('o')
                        }
                    })
                    completed_fixture_present =
                        Test-Path -LiteralPath $completedFixturePath `
                            -PathType Leaf
                    prewarm_tuple_current =
                        $currentPrewarmMatches.Count -eq 1
                    prewarm_tuple_revalidation =
                        $currentPrewarmSocket
                    valid = $backlogValid
                }
                $caseRecord.backlog_before_restart = $backlogEvidence
                Write-LabJson -Value $backlogEvidence -Path (
                    Join-Path $evidence `
                        "$($policy.name)-backlog-before-restart.json"
                ) | Out-Null
                if (-not $backlogValid) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) transfer backlog was not proved " +
                        'immediately before peer restart'
                    )
                }

                $oldPeerPid = $currentPeerPid
                $restartPath = Join-Path $coordination `
                    "$($policy.name)-restart.json"
                $restartedPath = Join-Path $coordination `
                    "peer-$($policy.name)-restarted.json"
                Write-LabJson -Value ([ordered]@{
                    schema = 'ese.v91.i03-restart-command/v1'
                    case_id = $caseId
                    run_nonce = $nonce
                    policy = $policy.name
                    action = 'restart-same-peer-source'
                    candidate_commit = $candidate.commit
                    candidate_emule_sha256 = $expectedHash
                    expected_old_process_id = $oldPeerPid
                    source_userhash_sha256 = $sourceIdentity
                }) -Path $restartPath | Out-Null
                $routeSamples = Join-Path $evidence `
                    "$($policy.name)-post-restart-samples.jsonl"
                $currentFailurePhase = 'post_restart_route'
                try {
                    $routeObservation = Wait-I03PostRestartRoute `
                        -Process $activeClient -ControlledServer $activeServer `
                        -WebPort $policy.web `
                        -TcpPort $policy.tcp -UdpPort $policy.udp `
                        -TargetAddresses @($peerV4Text, $peerV6Text) `
                        -TargetPort $PeerTcpPort `
                        -ControlAddress ([string]$routeV4.source_address) `
                        -ControlPort $activeServer.port `
                        -ExpectedFamily $policy.expected_family `
                        -PrewarmTuple `
                            ([string]$prewarm.selected_connection.tuple_key) `
                        -RestartAckPath $restartedPath `
                        -TimeoutSeconds $CaseTimeoutSeconds `
                        -ObservationSeconds $StableObservationSeconds `
                        -SamplesPath $routeSamples
                } catch {
                    $routeFailureMessage = [string]$_.Exception.Message
                    if ($routeFailureMessage -match
                        '^I03_COLLECTOR::') {
                        Stop-I03Fixture -Code 'COLLECTOR_UNAVAILABLE' `
                            -Reason 'Post-restart socket collector failed'
                    }
                    if ($routeFailureMessage -in @(
                        'I03_PRODUCT::CONTROLLED_ED2K_PROTOCOL',
                        'I03_PRODUCT::CONTROLLED_ED2K_TRANSPORT'
                    )) {
                        Stop-I03ProductFailure -Code 'API_CONTRACT' `
                            -SourceEvidence ([ordered]@{
                                process = $activeClientExpectedIdentity
                                error_kind =
                                    [string]$activeServer.state['error_kind']
                                error_code =
                                    [string]$activeServer.state['error_code']
                            }) -Reason 'Candidate violated controlled eD2K transport'
                    }
                    if ($routeFailureMessage -eq
                        'I03_FIXTURE::EXTERNAL_CONTAMINATION') {
                        Stop-I03Fixture -Code 'EXTERNAL_CONTAMINATION' `
                            -Reason 'Controlled eD2K endpoint was contaminated'
                    }
                    if ($routeFailureMessage -eq
                        'I03_FIXTURE::CONTROLLED_ED2K_SERVER_FAILED') {
                        Stop-I03Fixture -Code 'HARNESS_EXCEPTION' `
                            -Reason 'Controlled eD2K fixture failed post-restart'
                    }
                    if ($_.Exception.Message -match
                        'Client exited during post-restart') {
                        Stop-I03ProductFailure -Code 'CANDIDATE_EXITED' `
                            -SourceEvidence ([ordered]@{
                                process = $activeClientExpectedIdentity
                                phase = 'post_restart_route'
                            }) -Reason (
                            "$($policy.name) candidate exited during " +
                            "post-restart route selection: " +
                            $_.Exception.Message
                        )
                    }
                    throw
                }
                if ([int]$routeObservation.
                    unexpected_socket_observation_count -gt 0) {
                    Stop-I03ProductFailure `
                        -Code 'CANDIDATE_THIRD_PARTY_SOCKET' `
                        -SourceEvidence $routeObservation `
                        -Reason 'Candidate opened a non-allowlisted socket'
                }
                $restartAck = $routeObservation.restart_ack
                $restartAckExact =
                    $null -ne $restartAck -and
                    [string]$restartAck.schema -eq
                        'ese.v91.i03-peer-restarted/v1' -and
                    [string]$restartAck.case_id -eq $caseId -and
                    [string]$restartAck.run_nonce -eq $nonce -and
                    [string]$restartAck.policy -eq $policy.name -and
                    [string]$restartAck.candidate_commit -eq
                        $candidate.commit -and
                    [string]$restartAck.candidate_emule_sha256 -eq
                        $expectedHash -and
                    [int]$restartAck.old_process_id -eq $oldPeerPid -and
                    [int]$restartAck.process_id -gt 0 -and
                    [int]$restartAck.process_id -ne $oldPeerPid -and
                    [string]$restartAck.process_emule_sha256 -eq
                        $expectedHash -and
                    [string]$restartAck.source_userhash_sha256 -eq
                        $sourceIdentity -and
                    [bool]$restartAck.dual_stack_listener -and
                    [bool]$restartAck.api_isolation_valid
                if (-not $restartAckExact) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) same-identity peer restart " +
                        'was not proved'
                    )
                }
                $currentPeerPid = [int]$restartAck.process_id

                $observedConnections = @(
                    $routeObservation.current_established_connections
                )
                $observedSockets = @(
                    $routeObservation.current_socket_evidence
                )
                if (@($observedSockets | Where-Object {
                            -not [bool]$_.collector_ok
                        }).Count -gt 0) {
                    Stop-I03Fixture -Code 'COLLECTOR_AMBIGUOUS' -Reason (
                        "$($policy.name) route socket collector was " +
                        'unavailable or ambiguous'
                    )
                }
                if (-not $routeObservation.health_valid) {
                    $healthCode = if (
                        [int]$routeObservation.api_probe_count -eq 0 -or
                        [int]$routeObservation.api_failure_count -ne 0 -or
                        [double]$routeObservation.api_max_ms -ge 2000
                    ) { 'API_UNAVAILABLE' } else { 'UI_UNRESPONSIVE' }
                    $null = Add-I03ProductFailure -Code $healthCode `
                        -SourceEvidence $routeObservation `
                        -Reason "$($policy.name) candidate liveness invariant failed"
                }
                $decisionSocketProofs =
                    [System.Collections.Generic.List[object]]::new()
                $socketPairCount = [Math]::Min(
                    $observedSockets.Count,
                    $observedConnections.Count
                )
                for ($socketIndex = 0;
                    $socketIndex -lt $socketPairCount;
                    $socketIndex++) {
                    $connection = $observedConnections[$socketIndex]
                    $socket = $observedSockets[$socketIndex]
                    $expectedAddress = if (
                        [string]$connection.family -eq 'IPv6'
                    ) { $peerV6Text } else { $peerV4Text }
                    $expectedLocal = if (
                        [string]$connection.family -eq 'IPv6'
                    ) {
                        [string]$routeV6.source_address
                    } else {
                        [string]$routeV4.source_address
                    }
                    $attributionExact =
                        [int]$connection.owning_process -eq $activeClient.Id -and
                        [string]$connection.remote_address -eq $expectedAddress -and
                        [int]$connection.remote_port -eq $PeerTcpPort -and
                        [string]$connection.local_address -eq $expectedLocal
                    $decisionSocketProofs.Add([pscustomobject][ordered]@{
                        collector_ok = [bool]$socket.collector_ok
                        pid_matches = [bool]$socket.pid_matches
                        tuple_current_exact =
                            [bool]$socket.tuple_current_exact
                        local_address_assigned =
                            [bool]$socket.local_address_assigned
                        physical_nonvirtual =
                            [bool]$socket.physical_nonvirtual
                        attribution_exact = $attributionExact
                    })
                }

                $observedFamilies = @(
                    $observedConnections.family | Sort-Object -Unique
                )
                $routeDecision = Get-I03RouteSelectionDecision `
                    -Policy $policy.name -CollectorOk $true `
                    -FixtureCertified $currentFixtureCertified `
                    -Rows $observedConnections `
                    -SocketProofs @($decisionSocketProofs) `
                    -StableSeconds ([double]$routeObservation.
                        stable_observation_seconds) `
                    -RequiredStableSeconds $StableObservationSeconds `
                    -Contamination (
                        -not [bool]$routeObservation.prewarm_disappeared -or
                        [int]$routeObservation.other_pid_connection_count -ne 0
                    ) `
                    -AmbiguousSelection (
                        [bool]$routeObservation.ambiguous_family_selection -or
                        [int]$routeObservation.
                            duplicate_target_observation_count -ne 0
                    ) `
                    -WrongFamilyObserved (
                        [int]$routeObservation.
                            wrong_family_observation_count -ne 0
                    )
                if ([string]$routeDecision.status -ceq 'LAB_BLOCKED') {
                    Stop-I03Fixture -Code ([string]$routeDecision.code) `
                        -Reason 'Route decision evidence was unavailable or contaminated'
                }
                if ([string]$routeDecision.status -ceq
                    'PRODUCT_INVARIANT') {
                    $null = Add-I03ProductFailure `
                        -Code ([string]$routeDecision.code) `
                        -SourceEvidence $routeObservation `
                        -Reason "$($policy.name) route-selection invariant failed"
                }
                $productMatch = [bool]$routeDecision.product_match -and
                    [bool]$routeObservation.health_valid

                $donePath = Join-Path $coordination `
                    "$($policy.name)-done.json"
                $completePath = Join-Path $coordination `
                    "peer-$($policy.name)-complete.json"
                Write-LabJson -Value ([ordered]@{
                    schema = 'ese.v91.i03-done-command/v1'
                    case_id = $caseId
                    run_nonce = $nonce
                    policy = $policy.name
                    candidate_commit = $candidate.commit
                    candidate_emule_sha256 = $expectedHash
                    source_process_id = $currentPeerPid
                    client_process_id = $activeClient.Id
                    route_observed = $observedConnections.Count -gt 0
                    observed_family = if (
                        $observedFamilies.Count -eq 1
                    ) {
                        [string]$observedFamilies[0]
                    } else { $observedFamilies -join '+' }
                    observed_families = $observedFamilies
                    expected_connection_count =
                        $observedConnections.Count
                    observed_connections = $observedConnections
                }) -Path $donePath | Out-Null
                $completeWait = Wait-I03JsonFile -Path $completePath `
                    -StopPath $stopPath -TimeoutSeconds 30
                if ($null -eq $completeWait -or
                    $completeWait.kind -ne 'value') {
                    Stop-I03Fixture -Reason (
                        "Peer did not complete $($policy.name) barrier"
                    )
                }
                $peerComplete = $completeWait.value
                Write-LabJson -Value $peerComplete -Path (
                    Join-Path $evidence `
                        "$($policy.name)-peer-complete.json"
                ) | Out-Null
                $completeFamilies = @(
                    $peerComplete.observed_families |
                        ForEach-Object { [string]$_ } |
                        Sort-Object -Unique
                )
                $peerCompleteExact =
                    [string]$peerComplete.schema -eq
                        'ese.v91.i03-peer-complete/v1' -and
                    [string]$peerComplete.case_id -eq $caseId -and
                    [string]$peerComplete.run_nonce -eq $nonce -and
                    [string]$peerComplete.policy -eq $policy.name -and
                    [string]$peerComplete.candidate_commit -eq
                        $candidate.commit -and
                    [string]$peerComplete.candidate_emule_sha256 -eq
                        $expectedHash -and
                    [int]$peerComplete.source_process_id -eq
                        $currentPeerPid -and
                    [string]$peerComplete.source_process_emule_sha256 -eq
                        $expectedHash -and
                    [string]$peerComplete.source_userhash_sha256 -eq
                        $sourceIdentity -and
                    [bool]$peerComplete.route_observed -eq
                        ($observedConnections.Count -gt 0) -and
                    ($completeFamilies -join ',') -eq
                        ($observedFamilies -join ',') -and
                    @($peerComplete.inbound_connections).Count -eq
                        $observedConnections.Count -and
                    [bool]$peerComplete.api.available -and
                    [bool]$peerComplete.api.isolation_valid
                if (-not $peerCompleteExact) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) final peer barrier is not exact"
                    )
                }
                foreach ($outbound in $observedConnections) {
                    $inverse = @(
                        $peerComplete.inbound_connections |
                            Where-Object {
                                $expectedPeerLocal = if (
                                    [string]$outbound.family -eq 'IPv4'
                                ) {
                                    $peerLocalV4Text
                                } else {
                                    [string]$outbound.remote_address
                                }
                                $remoteTupleExact =
                                    [string]$_.remote_address -eq
                                        [string]$outbound.local_address -and
                                    [int]$_.remote_port -eq
                                        [int]$outbound.local_port
                                $natTranslated = [string]$outbound.family -eq
                                    'IPv4' -and
                                    $peerV4Text -ne $peerLocalV4Text
                                [string]$_.family -eq
                                    [string]$outbound.family -and
                                [string]$_.local_address -eq
                                    $expectedPeerLocal -and
                                [int]$_.local_port -eq
                                    [int]$outbound.remote_port -and
                                ($natTranslated -or $remoteTupleExact) -and
                                [int]$_.owning_process -eq
                                    $currentPeerPid
                            }
                    )
                    if ($inverse.Count -ne 1) {
                        Stop-I03Fixture -Reason (
                            "$($policy.name) final route lacks a unique " +
                            'correlated peer tuple'
                        )
                    }
                }
                $routeObservation | Add-Member -NotePropertyName `
                    observed_connections -NotePropertyValue `
                    $observedConnections -Force
                $routeObservation | Add-Member -NotePropertyName `
                    observed_families -NotePropertyValue `
                    $observedFamilies -Force
                $routeObservation | Add-Member -NotePropertyName `
                    product_match -NotePropertyValue $productMatch -Force
                $routeObservation | Add-Member -NotePropertyName `
                    ipv4_nat_correlation -NotePropertyValue `
                    ([pscustomobject][ordered]@{
                        nat_mapped =
                            $peerV4Text -ne $peerLocalV4Text
                        peer_observed_ipv4 = @(
                            $peerComplete.inbound_connections |
                                Where-Object family -eq 'IPv4'
                        )
                    }) -Force
                Write-LabJson -Value $routeObservation -Path (
                    Join-Path $evidence `
                        "$($policy.name)-post-restart.json"
                ) | Out-Null
                $caseRecord.post_restart = $routeObservation
                $caseRecord.peer_complete = $peerComplete
                $caseRecord.fixture_valid = $true
                $caseRecord.product_match = $productMatch
            } catch {
                $caseRecord.runtime_error = $_.Exception.Message
                throw
            } finally {
                $clientStopped = $true
                # Mark the server stop as expected before the candidate closes
                # its control-plane socket, otherwise EOF can be misclassified
                # as a fixture-server failure.
                if ($null -ne $activeServer) {
                    $caseServerStop =
                        Stop-I03ControlledEd2kServer `
                            -Server $activeServer
                    if (-not $caseServerStop.stopped -or
                        $caseServerStop.error) {
                        $allControlServersStopped = $false
                        $cleanupFailures.Add(
                            "$($policy.name) controlled server cleanup failed: " +
                            [string]$caseServerStop.error
                        )
                    }
                    $expectedServerEvidenceFields = @(
                        'schema', 'run_nonce', 'policy', 'listen_address',
                        'listen_port', 'high_id', 'login_at_utc',
                        'stopped_at_utc', 'phase', 'logged_in', 'reply_sent',
                        'candidate_attributed', 'attributed_process_id',
                        'login_protocol', 'login_opcode',
                        'login_payload_bytes', 'login_payload_sha256',
                        'login_advertised_tcp_port', 'frames_received',
                        'status_frames_sent', 'accepted_remote',
                        'error_kind', 'error_code'
                    )
                    $actualServerEvidenceFields = if (
                        $null -eq $caseServerStop.evidence
                    ) { @() } else {
                        @($caseServerStop.evidence.PSObject.Properties.Name)
                    }
                    if ($null -eq $caseServerStop.evidence -or
                        $actualServerEvidenceFields.Count -ne
                            $expectedServerEvidenceFields.Count -or
                        @($expectedServerEvidenceFields | Where-Object {
                            $actualServerEvidenceFields -cnotcontains $_
                        }).Count -ne 0 -or
                        [string]$caseServerStop.evidence.schema -cne
                            'ese.v91.i03-controlled-ed2k-server/v1' -or
                        -not [bool]$caseServerStop.evidence.logged_in -or
                        -not [bool]$caseServerStop.evidence.reply_sent -or
                        -not [bool]$caseServerStop.evidence.
                            candidate_attributed -or
                        [int]$caseServerStop.evidence.
                            attributed_process_id -ne [int]$activeClient.Id -or
                        [string]$caseServerStop.evidence.error_kind -cne
                            'none' -or
                        [string]$caseServerStop.evidence.error_code -cne
                            'NONE') {
                        $cleanupFailures.Add(
                            "$($policy.name) controlled server evidence is incomplete"
                        )
                    }
                }
                if ($null -ne $activeClient) {
                    $clientStop = Stop-I03OwnedProcess `
                        -Process $activeClient -ExpectedPath $activeClientExe `
                        -ExpectedIdentity $activeClientExpectedIdentity
                    $clientStopped = [bool]$clientStop.stopped
                    if (-not $clientStopped -or
                        -not $clientStop.collector_ok -or
                        $clientStop.unexpected_descendant_count -ne 0) {
                        $allClientsStopped = $false
                        $cleanupFailures.Add(
                            "$($policy.name) client process remains running"
                        )
                    }
                }
                if ($caseNode -and $null -ne $packageIdentityBefore -and
                    (Test-Path -LiteralPath $caseNode -PathType Container)) {
                    $caseNodeTerminalBinding =
                        Test-I03PreparedNodeBinding -NodePath $caseNode `
                            -PackageIdentity $packageIdentityBefore `
                            -Phase Terminal
                    Write-LabJson -Value $caseNodeTerminalBinding -Path (
                        Join-Path $evidence `
                            "$($policy.name)-prepared-node-binding-terminal.json"
                    ) | Out-Null
                    if (-not [bool]$caseNodeTerminalBinding.collector_ok -or
                        -not [bool]$caseNodeTerminalBinding.bound) {
                        $cleanupFailures.Add(
                            "$($policy.name) prepared static program files changed"
                        )
                    }
                }
                $clientHashAfter = if ($caseExe -and
                    (Test-Path -LiteralPath $caseExe -PathType Leaf)) {
                    Get-LabSha256 -Path $caseExe
                } else { '' }
                if ($clientHashAfter -and
                    $clientHashAfter -ne $expectedHash) {
                    $cleanupFailures.Add(
                        "$($policy.name) prepared executable changed"
                    )
                }
                if ($caseExe) {
                    $nodeBindingUnchanged =
                        $null -ne $caseNodeTerminalBinding -and
                        [bool]$caseNodeTerminalBinding.collector_ok -and
                        [bool]$caseNodeTerminalBinding.bound
                    $preparedBinaries.Add([pscustomobject][ordered]@{
                        policy = $policy.name
                        path = $caseExe
                        expected_sha256 = $expectedHash
                        after_sha256 = $clientHashAfter
                        initial_node_binding = $caseNodeInitialBinding
                        terminal_node_binding = $caseNodeTerminalBinding
                        unchanged = $clientHashAfter -eq $expectedHash -and
                            $nodeBindingUnchanged
                    })
                }
                $caseRecord.cleanup = [ordered]@{
                    client_stopped = $clientStopped
                    client_executable_sha256_after = $clientHashAfter
                    prepared_node_initial_binding =
                        $caseNodeInitialBinding
                    prepared_node_terminal_binding =
                        $caseNodeTerminalBinding
                    controlled_server_stopped = if (
                        $null -eq $caseServerStop
                    ) { $true } else { [bool]$caseServerStop.stopped }
                    controlled_server_evidence = if (
                        $null -eq $caseServerStop
                    ) { $null } else { $caseServerStop.evidence }
                }
                $caseRecord.finished_at_utc =
                    [DateTime]::UtcNow.ToString('o')
                if (-not $caseRecorded) {
                    $caseResults.Add([pscustomobject]$caseRecord)
                    $caseRecorded = $true
                }
                $activeClient = $null
                $activeClientExe = ''
                $activeClientExpectedIdentity = $null
                $activeServer = $null
            }
            if ($productFailures.Count -gt $failureCountBefore) {
                $caseRecord.product_match = $false
            }
        }

        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i03-stop-command/v1'
            case_id = $caseId
            run_nonce = $nonce
            action = 'stop-owned-processes'
            candidate_commit = $candidate.commit
            candidate_emule_sha256 = $expectedHash
            expected_last_source_process_id = $currentPeerPid
        }) -Path $stopPath | Out-Null
        $peerStopWritten = $true
        $peerResultWait = Wait-I03JsonFile -Path $peerResultPath `
            -TimeoutSeconds 30
        if ($null -eq $peerResultWait -or
            $peerResultWait.kind -ne 'value') {
            Stop-I03Fixture `
                -Reason 'Peer did not publish its final cleanup result'
        }
        $peerResult = $peerResultWait.value
    } catch {
        $runtimeFailure = $_.Exception.Message
        if ($runtimeFailure.StartsWith('I03_COLLECTOR::')) {
            $null = Add-I03TypedFailure -Status 'LAB_BLOCKED' `
                -Code 'COLLECTOR_UNAVAILABLE' `
                -Reason 'Coordinator collector failed'
            $runtimeFailure = 'I03_LAB_BLOCKED::COLLECTOR_UNAVAILABLE'
        } elseif (-not $runtimeFailure.StartsWith('I03_LAB_BLOCKED::') -and
            -not $runtimeFailure.StartsWith('I03_PRODUCT_INVARIANT::')) {
            $null = Add-I03TypedFailure -Status 'LAB_BLOCKED' `
                -Code 'HARNESS_EXCEPTION' -Reason $runtimeFailure
            $runtimeFailure = 'I03_LAB_BLOCKED::HARNESS_EXCEPTION'
        }
    } finally {
        if ($null -ne $baselineProbeV4) {
            try { $baselineProbeV4.client.Dispose() } catch {}
            $baselineProbeV4 = $null
        }
        if ($null -ne $baselineProbeV6) {
            try { $baselineProbeV6.client.Dispose() } catch {}
            $baselineProbeV6 = $null
        }
        if ($null -ne $activeServer) {
            $serverStop = Stop-I03ControlledEd2kServer `
                -Server $activeServer
            if (-not $serverStop.stopped -or $serverStop.error) {
                $allControlServersStopped = $false
                $cleanupFailures.Add(
                    'active controlled server remained after outer cleanup'
                )
            }
            $activeServer = $null
        }
        if ($null -ne $activeClient) {
            $clientStop = Stop-I03OwnedProcess -Process $activeClient `
                -ExpectedPath $activeClientExe `
                -ExpectedIdentity $activeClientExpectedIdentity
            if (-not $clientStop.stopped -or
                -not $clientStop.collector_ok -or
                $clientStop.unexpected_descendant_count -ne 0) {
                $allClientsStopped = $false
                $cleanupFailures.Add(
                    'active client process remained after outer cleanup'
                )
            }
            $activeClient = $null
        }
        if ($null -ne $mutationBaseline) {
            try {
                $mutationCleanup = Complete-I03MutationTransaction `
                    -Baseline $mutationBaseline
                if (-not [bool]$mutationCleanup.complete) {
                    $cleanupFailures.Add(
                        'startup registry or forbidden system state changed'
                    )
                }
            } catch {
                $cleanupFailures.Add(
                    'startup registry/system-state restoration failed'
                )
            }
        } else {
            $cleanupFailures.Add('mutation baseline was not captured')
        }
        if (-not $peerStopWritten) {
            try {
                Write-LabJson -Value ([ordered]@{
                    schema = 'ese.v91.i03-stop-command/v1'
                    case_id = $caseId
                    run_nonce = $nonce
                    action = 'stop-owned-processes'
                    candidate_commit = $candidate.commit
                    candidate_emule_sha256 = $expectedHash
                    expected_last_source_process_id = $currentPeerPid
                }) -Path $stopPath | Out-Null
                $peerStopWritten = $true
            } catch {
                $cleanupFailures.Add(
                    "Could not publish peer stop: $($_.Exception.Message)"
                )
            }
        }
        if ($null -eq $peerResult -and $null -ne $peerReady) {
            try {
                $latePeerResult = Wait-I03JsonFile `
                    -Path $peerResultPath -TimeoutSeconds 30
                if ($null -ne $latePeerResult -and
                    $latePeerResult.kind -eq 'value') {
                    $peerResult = $latePeerResult.value
                }
            } catch {
                $cleanupFailures.Add(
                    "Peer result wait failed: $($_.Exception.Message)"
                )
            }
        }
        if ($null -ne $peerResult) {
            try {
                Write-LabJson -Value $peerResult -Path (
                    Join-Path $evidence 'peer-result.json'
                ) | Out-Null
            } catch {
                $cleanupFailures.Add(
                    "Peer result copy failed: $($_.Exception.Message)"
                )
            }
        }
        try {
            $candidateAfter = Get-LabCandidateInfo `
                -PackagePath $PackagePath -ExpectedCommit $Commit
            $packageIdentityAfter =
                Get-I03PackageIdentity -PackagePath $candidate.package_path
            $packageZipBindingAfter = Get-I03ZipPackageBinding `
                -ZipPath $candidateZip `
                -ExpectedZipSha256 $expectedZipHash `
                -PackageIdentity $packageIdentityAfter
            Write-LabJson -Value $packageIdentityAfter -Path (
                Join-Path $evidence 'package-manifest-after.json'
            ) | Out-Null
            Write-LabJson -Value $packageZipBindingAfter -Path (
                Join-Path $evidence 'package-zip-binding-after.json'
            ) | Out-Null
            $packageManifestUnchanged =
                $null -ne $packageIdentityBefore -and
                $packageIdentityAfter.manifest_sha256 -eq
                    $packageIdentityBefore.manifest_sha256 -and
                $packageIdentityAfter.file_count -eq
                    $packageIdentityBefore.file_count -and
                $packageIdentityAfter.total_bytes -eq
                    $packageIdentityBefore.total_bytes
            $packageZipBindingUnchanged =
                $null -ne $packageZipBindingBefore -and
                $packageZipBindingAfter.verified -and
                $packageZipBindingAfter.zip_sha256 -eq
                    $packageZipBindingBefore.zip_sha256 -and
                $packageZipBindingAfter.zip_bytes -eq
                    $packageZipBindingBefore.zip_bytes -and
                $packageZipBindingAfter.manifest_sha256 -eq
                    $packageZipBindingBefore.manifest_sha256
            $candidateUnchanged =
                $candidateAfter.emule_sha256 -eq $expectedHash -and
                $candidateAfter.ese_server_sha256 -eq
                    $candidate.ese_server_sha256 -and
                $candidateAfter.build_info_sha256 -eq
                    $candidate.build_info_sha256 -and
                $packageManifestUnchanged -and
                $packageZipBindingUnchanged
        } catch {
            $cleanupFailures.Add(
                "Candidate revalidation failed: $($_.Exception.Message)"
            )
        }
        if (-not $candidateUnchanged) {
            $cleanupFailures.Add(
                'Candidate package changed during V91-I03'
            )
        }
    }

    $terminalNetworkCleanup = Get-I03TerminalSocketCleanupEvidence `
        -Ports @(
            $PeerTcpPort, $PeerUdpPort, $PeerWebPort,
            $AutoTcpPort, $AutoUdpPort, $AutoWebPort,
            $PreferredTcpPort, $PreferredUdpPort, $PreferredWebPort,
            @($controlledServerPorts)
        ) -OwnedProcessIds @($ownedCandidateProcessIds)
    Write-LabJson -Value $terminalNetworkCleanup -Path (
        Join-Path $evidence 'terminal-network-cleanup.json'
    ) | Out-Null
    if (-not [bool]$terminalNetworkCleanup.collector_ok -or
        -not [bool]$terminalNetworkCleanup.complete) {
        $cleanupFailures.Add('terminal network cleanup is incomplete')
    }
    $terminalProcessCleanup = Get-I03EmuleProcessCensus
    Write-LabJson -Value $terminalProcessCleanup -Path (
        Join-Path $evidence 'terminal-emule-process-census.json'
    ) | Out-Null
    if (-not [bool]$terminalProcessCleanup.collector_ok -or
        [int]$terminalProcessCleanup.process_count -ne 0) {
        $cleanupFailures.Add('terminal eMule process census is not empty')
    }

    if ($null -ne $peerResult) {
        try {
            $peerFailureProtocolExact =
                $peerResult.failure_records -is [System.Array] -and
                $peerResult.failure_source_manifest -is [System.Array]
            $peerValidatedFailures =
                [System.Collections.Generic.List[object]]::new()
            if ($peerFailureProtocolExact) {
                foreach ($record in @($peerResult.failure_records)) {
                    if (-not (Test-I03FailureRecord -Record $record `
                        -ExpectedCaseId $caseId -ExpectedRunNonce $nonce `
                        -ExpectedRole 'Peer' `
                        -ExpectedCommit $candidate.commit `
                        -ExpectedEmuleSha256 $expectedHash `
                        -ExpectedZipSha256 $expectedZipHash `
                        -ExpectedManifestSha256 `
                            $packageIdentityBefore.manifest_sha256)) {
                        $peerFailureProtocolExact = $false
                        break
                    }
                    $peerValidatedFailures.Add($record)
                }
            }
            if ($peerFailureProtocolExact) {
                $peerFailureSourceVerification =
                    Test-I03PersistedFailureSources `
                        -Manifest @($peerResult.failure_source_manifest) `
                        -Root $coordination -ExpectedCaseId $caseId `
                        -ExpectedRunNonce $nonce -ExpectedRole 'Peer'
                $peerFailureProtocolExact =
                    [bool]$peerFailureSourceVerification.ok
            }
            if ($peerFailureProtocolExact) {
                $peerSourceHashes = @(
                    $peerFailureSourceVerification.source_sha256
                )
                $peerSourceBindings = @(
                    $peerFailureSourceVerification.
                        trusted_binding_sha256
                )
                $peerProductProofs = @($peerValidatedFailures |
                    Where-Object status -CEQ 'PRODUCT_INVARIANT' |
                    ForEach-Object { $_.proofs })
                if (@($peerProductProofs | Where-Object {
                            [string]$_.source_evidence_sha256 -cnotin
                                $peerSourceHashes
                        }).Count -gt 0 -or
                    @($peerSourceHashes | Where-Object {
                            [string]$_ -cnotin @(
                                $peerProductProofs.source_evidence_sha256
                            )
                        }).Count -gt 0 -or
                    @($peerProductProofs | Where-Object {
                            [string]$_.binding_sha256 -cnotin
                                $peerSourceBindings
                        }).Count -gt 0 -or
                    @($peerSourceBindings | Where-Object {
                            [string]$_ -cnotin @(
                                $peerProductProofs.binding_sha256
                            )
                        }).Count -gt 0) {
                    $peerFailureProtocolExact = $false
                }
            }
            if ($peerFailureProtocolExact) {
                $peerProductFailureCount = @($peerValidatedFailures |
                    Where-Object status -CEQ 'PRODUCT_INVARIANT').Count
                $peerLabFailureCount = @($peerValidatedFailures |
                    Where-Object status -CEQ 'LAB_BLOCKED').Count
                $peerStatusFailureExact =
                    ([string]$peerResult.status -ceq 'COMPLETE' -and
                        $peerProductFailureCount -eq 0 -and
                        $peerLabFailureCount -eq 0) -or
                    ([string]$peerResult.status -ceq
                        'PRODUCT_INVARIANT' -and
                        $peerProductFailureCount -gt 0) -or
                    ([string]$peerResult.status -ceq 'LAB_BLOCKED' -and
                        $peerProductFailureCount -eq 0 -and
                        $peerLabFailureCount -gt 0)
                if (-not $peerStatusFailureExact) {
                    $peerFailureProtocolExact = $false
                }
            }
            if ($peerFailureProtocolExact) {
                $peerProvenProductFailure = $peerProductFailureCount -gt 0
                foreach ($record in $peerValidatedFailures) {
                    $failureRecords.Add($record)
                    if ([string]$record.status -ceq
                        'PRODUCT_INVARIANT') {
                        foreach ($proof in @($record.proofs)) {
                            if ([string]$proof.binding_sha256 -cin
                                $peerSourceBindings) {
                                [void]$trustedProofBindings.Add(
                                    [string]$proof.binding_sha256
                                )
                            }
                        }
                    }
                }
            }
            $peerCleanupExact =
                [string]$peerResult.schema -eq
                    'ese.v91.i03-peer-result/v1' -and
                [string]$peerResult.case_id -eq $caseId -and
                [string]$peerResult.run_nonce -eq $nonce -and
                [string]$peerResult.candidate_commit -eq
                    $candidate.commit -and
                [string]$peerResult.candidate_emule_sha256 -eq
                    $expectedHash -and
                [string]$peerResult.candidate_zip_sha256 -eq
                    $expectedZipHash -and
                [string]$peerResult.candidate_package_manifest_sha256 -eq
                    $packageIdentityBefore.manifest_sha256 -and
                [string]$peerResult.lab_user_sid_sha256 -match
                    '^[0-9a-f]{64}$' -and
                $peerFailureProtocolExact -and
                [string]$peerResult.source_userhash_sha256 -eq
                    $sourceIdentity -and
                [bool]$peerResult.cleanup.source_process_stopped -and
                [bool]$peerResult.cleanup.candidate_package_unchanged -and
                [bool]$peerResult.cleanup.
                    extracted_package_manifest_unchanged -and
                [bool]$peerResult.cleanup.package_zip_binding_unchanged -and
                [bool]$peerResult.cleanup.autostart_restored_exact -and
                [bool]$peerResult.cleanup.
                    ed2k_association_restored_exact -and
                [bool]$peerResult.cleanup.forbidden_state_unchanged -and
                [bool]$peerResult.cleanup.prepared_executable_unchanged -and
                @($peerResult.cleanup.failures).Count -eq 0
            $peerResultExact = $peerCleanupExact -and
                [string]$peerResult.status -eq 'COMPLETE' -and
                [int]$peerResult.barriers_completed -eq 2 -and
                [int]$peerResult.expected_barriers -eq 2
        } catch {
            $peerResultExact = $false
            $peerCleanupExact = $false
            $cleanupFailures.Add(
                "Peer result validation failed: $($_.Exception.Message)"
            )
        }
    }
    if (-not $peerResultExact -and -not (
        ([bool]$productAdjudication.runtime_failure -or
            $peerProvenProductFailure) -and
        $peerCleanupExact
    )) {
        Add-I03BlockedReason `
            -Reason 'Peer completion/cleanup evidence is not exact'
    }
    if ($null -ne $runtimeFailure -and
        -not $runtimeFailure.StartsWith('I03_LAB_BLOCKED::') -and
        -not $runtimeFailure.StartsWith('I03_PRODUCT_INVARIANT::')) {
        Add-I03BlockedReason -Reason 'HARNESS_EXCEPTION'
    }
    if ($cleanupFailures.Count -gt 0) {
        Add-I03BlockedReason `
            -Reason 'Transactional owned-process/server cleanup was incomplete'
    }
    $caseFixtureValid = $caseResults.Count -eq 2 -and
        @($caseResults | Where-Object {
            -not [bool]$_.fixture_valid
        }).Count -eq 0
    $productRuntimeFixtureValid =
        ([bool]$productAdjudication.runtime_failure -or
            $peerProvenProductFailure) -and
        $caseResults.Count -ge 1 -and
        $null -ne $caseResults[$caseResults.Count - 1].client -and
        $null -ne $caseResults[$caseResults.Count - 1].
            controlled_server -and
        $null -ne $caseResults[$caseResults.Count - 1].
            dualstack_rearm
    if (-not $caseFixtureValid -and
        -not $productRuntimeFixtureValid -and
        $blockedReasons.Count -eq 0) {
        Add-I03BlockedReason `
            -Reason 'Both Auto and Preferred fixtures did not complete'
    }
    $preparedBinariesAllValid =
        $preparedBinaries.Count -ge 1 -and
        @($preparedBinaries | Where-Object {
            -not [bool]$_.unchanged
        }).Count -eq 0
    $preparedBinariesValid = $preparedBinariesAllValid -and (
        $preparedBinaries.Count -eq 2 -or
        $productRuntimeFixtureValid
    )
    if (-not $preparedBinariesValid) {
        Add-I03BlockedReason `
            -Reason 'Prepared candidate binary revalidation is incomplete'
    }
    $cleanupComplete = $allClientsStopped -and
        $allControlServersStopped -and
        $null -ne $terminalNetworkCleanup -and
        [bool]$terminalNetworkCleanup.complete -and
        $null -ne $terminalProcessCleanup -and
        [bool]$terminalProcessCleanup.collector_ok -and
        [int]$terminalProcessCleanup.process_count -eq 0 -and
        ($peerResultExact -or
            (([bool]$productAdjudication.runtime_failure -or
                $peerProvenProductFailure) -and $peerCleanupExact)) -and
        $candidateUnchanged -and $preparedBinariesValid -and
        $cleanupFailures.Count -eq 0
    $cleanup = [ordered]@{
        schema = 'ese.v91.i03-cleanup/v1'
        captured_at_utc = Get-LabUtcTimestamp
        all_candidate_clients_stopped = $allClientsStopped
        all_controlled_servers_stopped = $allControlServersStopped
        peer_stop_command_written = $peerStopWritten
        peer_cleanup_exact = $peerCleanupExact
        peer_full_completion_exact = $peerResultExact
        candidate_package_unchanged = $candidateUnchanged
        extracted_package_manifest_unchanged =
            $packageManifestUnchanged
        package_zip_binding_unchanged = $packageZipBindingUnchanged
        prepared_binaries = @($preparedBinaries)
        mutation_cleanup = $mutationCleanup
        autostart_restored_exact = $null -ne $mutationCleanup -and
            [bool]$mutationCleanup.autostart_restored_exact
        ed2k_association_restored_exact =
            $null -ne $mutationCleanup -and
            [bool]$mutationCleanup.ed2k_association_restored_exact
        forbidden_state_unchanged = $null -ne $mutationCleanup -and
            [bool]$mutationCleanup.forbidden_state_unchanged
        terminal_network = $terminalNetworkCleanup
        terminal_processes = $terminalProcessCleanup
        retained_by_design = @(
            'coordinator OutputRoot profiles',
            'peer OutputRoot profile',
            'fixture files',
            'evidence',
            'nonce-scoped coordination records'
        )
        complete = $cleanupComplete
        failures = @($cleanupFailures)
    }
    $localFailureSourceVerification = Test-I03PersistedFailureSources `
        -Manifest @($failureSourceFiles) -Root $evidence `
        -ExpectedCaseId $caseId -ExpectedRunNonce $nonce `
        -ExpectedRole 'Coordinator'
    $failureSourceEvidenceComplete =
        [bool]$localFailureSourceVerification.ok
    $localSourceHashes = @(
        $localFailureSourceVerification.source_sha256
    )
    $localTrustedBindings = @(
        $localFailureSourceVerification.trusted_binding_sha256
    )
    $localProductSourceHashes = @($failureRecords |
        Where-Object {
            [string]$_.role -ceq 'Coordinator' -and
            [string]$_.status -ceq 'PRODUCT_INVARIANT'
        } | ForEach-Object { $_.proofs } | ForEach-Object {
            [string]$_.source_evidence_sha256
        } | Sort-Object -Unique)
    $localProductBindingHashes = @($failureRecords |
        Where-Object {
            [string]$_.role -ceq 'Coordinator' -and
            [string]$_.status -ceq 'PRODUCT_INVARIANT'
        } | ForEach-Object { $_.proofs } | ForEach-Object {
            [string]$_.binding_sha256
        } | Sort-Object -Unique)
    if (@($localProductSourceHashes | Where-Object {
                [string]$_ -cnotin $localSourceHashes
            }).Count -gt 0 -or
        @($localSourceHashes | Where-Object {
                [string]$_ -cnotin $localProductSourceHashes
            }).Count -gt 0 -or
        @($localProductBindingHashes | Where-Object {
                [string]$_ -cnotin $localTrustedBindings
            }).Count -gt 0 -or
        @($localTrustedBindings | Where-Object {
                [string]$_ -cnotin $localProductBindingHashes
            }).Count -gt 0) {
        $failureSourceEvidenceComplete = $false
    }
    $trustedProofBindings.Clear()
    foreach ($record in $failureRecords) {
        if ([string]$record.status -cne 'PRODUCT_INVARIANT') {
            continue
        }
        $verifiedBindings = if ([string]$record.role -ceq 'Peer' -and
            $null -ne $peerFailureSourceVerification -and
            [bool]$peerFailureSourceVerification.ok) {
            @($peerFailureSourceVerification.trusted_binding_sha256)
        } elseif ([string]$record.role -ceq 'Coordinator' -and
            $failureSourceEvidenceComplete) {
            $localTrustedBindings
        } else { @() }
        foreach ($proof in @($record.proofs)) {
            if ([string]$proof.binding_sha256 -cin $verifiedBindings) {
                [void]$trustedProofBindings.Add(
                    [string]$proof.binding_sha256
                )
            }
        }
    }
    if (-not $failureSourceEvidenceComplete) {
        Add-I03BlockedReason -Reason 'EVIDENCE_INCOMPLETE'
        $currentPolicyName = 'none'
        $currentFailurePhase = 'evidence_finalize'
        $currentFixtureCertified = $false
        $null = Add-I03TypedFailure -Status 'LAB_BLOCKED' `
            -Code 'EVIDENCE_INCOMPLETE' `
            -Reason 'Persisted product failure sources did not revalidate'
    }
    if ($cleanupFailures.Count -gt 0) {
        $currentPolicyName = 'none'
        $currentFailurePhase = 'cleanup'
        $currentFixtureCertified = $false
        $null = Add-I03TypedFailure -Status 'LAB_BLOCKED' `
            -Code 'CLEANUP_INCOMPLETE' `
            -Reason 'Transactional cleanup was incomplete'
    }
    [object[]]$cleanupIncidentCodes = @()
    if ($cleanupFailures.Count -gt 0) {
        $cleanupIncidentCodes = @('CLEANUP_INCOMPLETE')
    }
    foreach ($failureRecord in $failureRecords) {
        $failureRecord.cleanup.complete = $cleanupComplete
        $failureRecord.cleanup.incident_codes = @($cleanupIncidentCodes)
    }
    Write-LabJson -Value $cleanup -Path $cleanupPath | Out-Null

    $clockValid = $null -ne $clockEvidence -and
        [bool]$clockEvidence.certified_within_1000_ms
    $adjudicationFixtureValid = $peerReadyExact -and $topologyValid -and
        $null -ne $baselineEvidence -and $clockValid -and
        ($caseFixtureValid -or $productRuntimeFixtureValid)
    $bothPoliciesPass = $caseResults.Count -eq 2 -and
        @($caseResults | Where-Object {
            -not [bool]$_.fixture_valid -or
            -not [bool]$_.product_match
        }).Count -eq 0
    $evidenceComplete = $peerResultExact -and $candidateUnchanged -and
        $packageManifestUnchanged -and $packageZipBindingUnchanged
    $fixtureCompleteForPass = $adjudicationFixtureValid -and
        $blockedReasons.Count -eq 0
    $adjudication = Get-I03FormalAdjudication `
        -FailureRecords @($failureRecords) `
        -AllowedRolePolicyTuples @(
            'Coordinator|none', 'Coordinator|auto',
            'Coordinator|preferred', 'Peer|none', 'Peer|auto',
            'Peer|preferred'
        ) `
        -TrustedProofBindings @($trustedProofBindings) `
        -FixtureComplete $fixtureCompleteForPass `
        -BothPoliciesPass $bothPoliciesPass `
        -EvidenceComplete $evidenceComplete `
        -CleanupComplete $cleanupComplete `
        -ExpectedCaseId $caseId -ExpectedRunNonce $nonce `
        -ExpectedCommit $candidate.commit `
        -ExpectedEmuleSha256 $expectedHash `
        -ExpectedZipSha256 $expectedZipHash `
        -ExpectedManifestSha256 $packageIdentityBefore.manifest_sha256
    $formalStatus = [string]$adjudication.formal_status
    $fullFixtureValid = $formalStatus -ceq 'PASS'
    $controlledLoginValidated = $caseResults.Count -gt 0 -and
        @($caseResults | Where-Object {
            $null -eq $_.controlled_server -or
            -not [bool]$_.controlled_server.login.connected
        }).Count -eq 0
    $literalIPv4SourceValidated = $caseResults.Count -gt 0 -and
        @($caseResults | Where-Object {
            -not [bool]$_.literal_ipv4_source_link_validated
        }).Count -eq 0
    $dnsIsolationConfigured = $caseResults.Count -gt 0 -and
        @($caseResults | Where-Object {
            $null -eq $_.client -or
            [bool]$_.client.isolation_controls.update_notify -or
            [bool]$_.client.isolation_controls.serverlist_auto_update -or
            [bool]$_.client.isolation_controls.add_servers_from_server -or
            [bool]$_.client.isolation_controls.add_servers_from_client -or
            -not [bool]$_.client.isolation_controls.
                literal_control_server_address
        }).Count -eq 0
    $helloLearnedInCompletedCases = $caseResults.Count -gt 0 -and
        @($caseResults | Where-Object {
            $null -eq $_.prewarm -or
            -not [bool]$_.prewarm.hello.
                learned_public_ipv6_via_hello
        }).Count -eq 0
    $rearmProvedInCompletedCases = $caseResults.Count -gt 0 -and
        @($caseResults | Where-Object {
            $null -eq $_.dualstack_rearm -or
            -not [bool]$_.dualstack_rearm.peer.
                runtime_dualstack_rearmed
        }).Count -eq 0
    $backlogProvedInCompletedCases = $caseResults.Count -gt 0 -and
        @($caseResults | Where-Object {
            $null -eq $_.backlog_before_restart -or
            -not [bool]$_.backlog_before_restart.valid
        }).Count -eq 0
    $finishedAt = [DateTime]::UtcNow
    $summary = [ordered]@{
        schema = 'ese.v91.i03-route-selection/v1'
        case_id = $caseId
        formal_status = $formalStatus
        candidate = [ordered]@{
            commit = $candidate.commit
            version = $candidate.version
            expected_emule_sha256 = $expectedHash
            package_emule_sha256_before = $candidate.emule_sha256
            package_emule_sha256_after = if ($null -eq $candidateAfter) {
                ''
            } else { $candidateAfter.emule_sha256 }
            ese_server_sha256 = $candidate.ese_server_sha256
            build_info_sha256 = $candidate.build_info_sha256
            extracted_package_manifest_before = if (
                $null -eq $packageIdentityBefore
            ) { $null } else {
                [ordered]@{
                    sha256 = $packageIdentityBefore.manifest_sha256
                    file_count = $packageIdentityBefore.file_count
                    total_bytes = $packageIdentityBefore.total_bytes
                }
            }
            extracted_package_manifest_after = if (
                $null -eq $packageIdentityAfter
            ) { $null } else {
                [ordered]@{
                    sha256 = $packageIdentityAfter.manifest_sha256
                    file_count = $packageIdentityAfter.file_count
                    total_bytes = $packageIdentityAfter.total_bytes
                }
            }
            extracted_package_manifest_unchanged =
                $packageManifestUnchanged
            unchanged = $candidateUnchanged
            prepared_binaries = @($preparedBinaries)
        }
        run = [ordered]@{
            nonce = $nonce
            started_at_utc = $startedAt.ToString('o')
            finished_at_utc = $finishedAt.ToString('o')
            elapsed_seconds = [Math]::Round(
                ($finishedAt - $startedAt).TotalSeconds, 3
            )
            coordination_directory_name =
                Split-Path -Leaf $coordination
        }
        topology = [ordered]@{
            required = 'T1/T2 direct native'
            observed_class = $topologyClass
            proved = $topologyValid
            t1_proved = $topologyT1
            t2_proved = $topologyT2
            same_ipv4_physical_prefix = $sameIPv4PhysicalPrefix
            same_ipv6_physical_prefix = $sameIPv6PhysicalPrefix
            local_machine_id_sha256 = if (
                Get-Variable -Name localMachineId `
                    -ErrorAction SilentlyContinue
            ) { $localMachineId } else { '' }
            peer_machine_id_sha256 = if ($null -eq $peerReady) {
                ''
            } else { [string]$peerReady.peer.machine_id_sha256 }
            ipv4_route = $routeV4
            ipv6_route = $routeV6
            clocks = $clockEvidence
        }
        isolation = [ordered]@{
            netlab_enabled = $false
            kad_enabled = $false
            third_party_ed2k_servers = $false
            controlled_ed2k_scheduler = [ordered]@{
                type = 'same-host physical-IP minimal server'
                address = if ($null -eq $routeV4) {
                    ''
                } else { [string]$routeV4.source_address }
                OP_LOGINREQUEST_validated =
                    $controlledLoginValidated
                OP_IDCHANGE_high_id = [uint32]0x01000001
                static_only = $true
            }
            dns_dependency = $false
            dns_third_party_controls_configured =
                $dnsIsolationConfigured
            web_allowed_ips = '127.0.0.1'
            firewall_modified = $false
            adapters_modified = $false
            routes_modified = $false
            hosts_modified = $false
        }
        fixture = [ordered]@{
            valid_for_adjudication = $adjudicationFixtureValid
            full_two_policy_fixture_valid = $fullFixtureValid
            exact_peer_ready = $peerReadyExact
            exact_peer_result = $peerResultExact
            source_userhash_sha256 = $sourceIdentity
            same_peer_identity_across_restarts =
                $peerResultExact -and
                [string]$peerResult.source_userhash_sha256 -eq
                    $sourceIdentity
            literal_ipv4_source_only =
                $literalIPv4SourceValidated
            public_ipv6_learned_by_highid_hello =
                $helloLearnedInCompletedCases
            current_pid_dualstack_rearm_per_case =
                $rearmProvedInCompletedCases
            incomplete_transfer_backlog_before_restart =
                $backlogProvedInCompletedCases
            baseline = $baselineEvidence
        }
        policies = @($caseResults)
        product_failures = @($productFailures)
        failure_records = @($failureRecords)
        failure_source_manifest = @($failureSourceFiles)
        formal_adjudication = $adjudication
        blocked_reasons = @(
            $blockedReasons | Select-Object -Unique
        )
        runtime_error = $runtimeFailure
        cleanup = $cleanup
        evidence = [ordered]@{
            run = 'evidence\run.json'
            preflight = 'evidence\preflight.json'
            peer_ready = 'evidence\peer-ready.json'
            baseline = 'evidence\baseline.json'
            peer_result = 'evidence\peer-result.json'
            cleanup = 'evidence\cleanup.json'
            package_manifest_before =
                'evidence\package-manifest-before.json'
            package_manifest_after =
                'evidence\package-manifest-after.json'
            manual_peer_command =
                'evidence\MANUAL-PEER-COMMAND.txt'
            auto = [ordered]@{
                startup = 'evidence\auto-client-startup.json'
                rearm = 'evidence\auto-peer-rearm-ack.json'
                prewarm = 'evidence\auto-prewarm.json'
                backlog_before_restart =
                    'evidence\auto-backlog-before-restart.json'
                post_restart =
                    'evidence\auto-post-restart.json'
                peer_complete =
                    'evidence\auto-peer-complete.json'
                controlled_server =
                    'evidence\auto-controlled-ed2k-server.json'
            }
            preferred = [ordered]@{
                startup =
                    'evidence\preferred-client-startup.json'
                rearm =
                    'evidence\preferred-peer-rearm-ack.json'
                prewarm = 'evidence\preferred-prewarm.json'
                backlog_before_restart =
                    'evidence\preferred-backlog-before-restart.json'
                post_restart =
                    'evidence\preferred-post-restart.json'
                peer_complete =
                    'evidence\preferred-peer-complete.json'
                controlled_server =
                    'evidence\preferred-controlled-ed2k-server.json'
            }
        }
    }
    Write-LabJson -Value $summary -Path $privateSummaryPath | Out-Null
    $privateManifestPath = Join-Path $evidence 'private-manifest.json'
    $publicRootPrefix = [IO.Path]::GetFullPath(
        $publicEvidence
    ).TrimEnd('\') + '\'
    $outputRootPrefix = [IO.Path]::GetFullPath($output).TrimEnd('\') + '\'
    $coordinationRootPrefix = [IO.Path]::GetFullPath(
        $coordination
    ).TrimEnd('\') + '\'
    $outputPrivateRows = @(Get-ChildItem -LiteralPath $output -File `
        -Recurse -Force -ErrorAction Stop | Where-Object {
            -not $_.FullName.StartsWith(
                $publicRootPrefix,
                [StringComparison]::OrdinalIgnoreCase
            ) -and $_.FullName -cne $privateManifestPath
        } | ForEach-Object {
            [pscustomobject][ordered]@{
                scope = 'output-private-and-nodes'
                relative_path = $_.FullName.Substring(
                    $outputRootPrefix.Length
                )
                bytes = [Int64]$_.Length
                sha256 = Get-LabSha256 -Path $_.FullName
            }
        })
    $coordinationPrivateRows = @(Get-ChildItem -LiteralPath $coordination `
        -File -Recurse -Force -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    scope = 'coordination-private'
                    relative_path = $_.FullName.Substring(
                        $coordinationRootPrefix.Length
                    )
                    bytes = [Int64]$_.Length
                    sha256 = Get-LabSha256 -Path $_.FullName
                }
            })
    $privateFileRows = @(
        @($outputPrivateRows) + @($coordinationPrivateRows) |
            Sort-Object scope, relative_path
    )
    $privateManifest = [ordered]@{
        schema = 'ese.v91.i03-private-evidence-manifest/v1'
        case_id = $caseId
        run_nonce = $nonce
        retained_by_design = $true
        files = $privateFileRows
    }
    Write-LabJson -Value $privateManifest -Path $privateManifestPath | Out-Null
    $publicFailures = @($failureRecords | ForEach-Object {
        [pscustomobject][ordered]@{
            role = [string]$_.role
            policy = [string]$_.policy
            phase = [string]$_.phase
            status = [string]$_.status
            category = [string]$_.category
            code = [string]$_.code
            fixture_certified = [bool]$_.fixture_certified
            cleanup_complete = [bool]$_.cleanup.complete
            cleanup_incident_codes = @($_.cleanup.incident_codes)
        }
    })
    $publicSummary = [ordered]@{
        schema = 'ese.v91.i03-public-summary/v1'
        case_id = $caseId
        formal_status = $formalStatus
        candidate = [ordered]@{
            commit = $candidate.commit
            emule_sha256 = $expectedHash
            zip_sha256 = $expectedZipHash
            package_manifest_sha256 =
                $packageIdentityBefore.manifest_sha256
            package_unchanged = $candidateUnchanged
        }
        topology = [ordered]@{
            class = $topologyClass
            proved = $topologyValid
            t1_proved = $topologyT1
            t2_proved = $topologyT2
        }
        policies = @($caseResults | ForEach-Object {
            [pscustomobject][ordered]@{
                policy = [string]$_.policy
                ipv6_mode = [int]$_.ipv6_mode
                expected_family = [string]$_.expected_family
                fixture_valid = [bool]$_.fixture_valid
                product_match = [bool]$_.product_match
            }
        })
        adjudication = $adjudication
        failures = $publicFailures
        cleanup = [ordered]@{
            complete = $cleanupComplete
            candidate_package_unchanged = $candidateUnchanged
            package_manifest_unchanged = $packageManifestUnchanged
            package_zip_binding_unchanged = $packageZipBindingUnchanged
            process_cleanup_complete =
                $allClientsStopped -and $allControlServersStopped
            peer_cleanup_complete = $peerCleanupExact
            registry_and_system_state_exact =
                $null -ne $mutationCleanup -and
                [bool]$mutationCleanup.complete
        }
        retention = [ordered]@{
            private_artifacts_retained = $true
            private_file_count = $privateFileRows.Count + 1
            private_total_bytes = [Int64](
                ($privateFileRows | Measure-Object bytes -Sum).Sum +
                (Get-Item -LiteralPath $privateManifestPath).Length
            )
            private_artifact_manifest_sha256 =
                Get-LabSha256 -Path $privateManifestPath
            public_allowlist = @('summary.json', 'evidence-manifest.json')
        }
    }
    if (-not (Test-I03PublicEvidenceObject -Value $publicSummary)) {
        throw 'I03_PUBLIC_EVIDENCE::SUMMARY_REJECTED'
    }
    Write-LabJson -Value $publicSummary -Path $summaryPath | Out-Null
    $publicManifest = [ordered]@{
        schema = 'ese.v91.i03-public-evidence-manifest/v1'
        case_id = $caseId
        files = @(
            [ordered]@{
                name = 'summary.json'
                bytes = [Int64](Get-Item -LiteralPath $summaryPath).Length
                sha256 = Get-LabSha256 -Path $summaryPath
            }
        )
        private_artifacts_retained = $true
        private_artifact_manifest_sha256 =
            Get-LabSha256 -Path $privateManifestPath
        public_scan_passed = $true
    }
    if (-not (Test-I03PublicEvidenceObject -Value $publicManifest)) {
        throw 'I03_PUBLIC_EVIDENCE::MANIFEST_REJECTED'
    }
    $publicManifestPath = Join-Path $publicEvidence `
        'evidence-manifest.json'
    Write-LabJson -Value $publicManifest -Path $publicManifestPath | Out-Null
    if (-not (Test-I03PublicEvidenceText -Text (
            Get-Content -LiteralPath $summaryPath -Raw
        )) -or -not (Test-I03PublicEvidenceText -Text (
            Get-Content -LiteralPath $publicManifestPath -Raw
        )) -or -not (Test-I03PublicEvidenceDirectory `
            -Root $publicEvidence `
            -ExpectedFiles @('summary.json', 'evidence-manifest.json') `
            -PrivateManifestPath $privateManifestPath)) {
        throw 'I03_PUBLIC_EVIDENCE::POSTWRITE_SCAN_FAILED'
    }

    if ($formalStatus -eq 'FAIL') {
        throw (
            'V91-I03 FAIL: ' +
            (@($productFailures | ForEach-Object {
                [string]$_.code
            } | Select-Object -Unique) -join ',') +
            ". Evidence: $summaryPath"
        )
    }
    if ($formalStatus -eq 'BLOCKED') {
        throw (
            'V91-I03 BLOCKED: ' +
            (@($publicFailures | ForEach-Object {
                [string]$_.code
            } | Select-Object -Unique) -join ',') +
            ". Evidence: $summaryPath"
        )
    }
    Write-Host "V91-I03 PASS on exact candidate/$topologyClass`: $output" `
        -ForegroundColor Green
}

if ($Role -eq 'Peer') {
    Invoke-I03PeerRole
} else {
    Invoke-I03CoordinatorRole
}
