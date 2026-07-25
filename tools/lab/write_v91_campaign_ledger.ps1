[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$EvidenceRoot
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $EvidenceRoot).Path
$candidateCommit = '72a5a41ebeec1bd08bff7ed17df27782930d96e3'
$candidateSha256 = '82360915292df613320af889e7680c69efcf422df9d8052b3613041a0a42da14'
$cases = [System.Collections.Generic.List[object]]::new()

function Add-Case {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)]
        [ValidateSet('PASS', 'FAIL', 'BLOCKED')]
        [string]$Status,
        [Parameter(Mandatory = $true)][string]$Topology,
        [Parameter(Mandatory = $true)][string]$Reason,
        [string[]]$Evidence = @(),
        [bool]$Executed = $false,
        [string]$ExecutionState = 'NOT_EXECUTABLE'
    )

    foreach ($relative in $Evidence) {
        if (-not (Test-Path -LiteralPath (Join-Path $root $relative) -PathType Leaf)) {
            throw "Evidence declared by $Id is missing: $relative"
        }
    }
    $cases.Add([pscustomobject][ordered]@{
        id = $Id
        status = $Status
        required_topology = $Topology
        executed = $Executed
        execution_state = $ExecutionState
        reason = $Reason
        evidence = @($Evidence)
    })
}

Add-Case 'V91-A01' 'PASS' 'build' `
    'Fresh Core and Integration gates passed on the frozen commit; package selftest also passed.' `
    @('V91-A01\summary.json',
      'V91-A01-CORE-attempt4\summary.json',
      'V91-A01-INTEGRATION\summary.json',
      'V91-A01-INTEGRATION-attempt2\summary.json',
      'selftest-attempt4\evidence\G-SELFTEST-SUMMARY.json',
      'selftest-attempt5\evidence\G-SELFTEST-SUMMARY.json',
      'selftest-attempt6\evidence\G-SELFTEST-SUMMARY.json',
      'release-verification-attempt4\summary.json',
      'release-preflight-attempt2\summary.json',
      'release-zip-parity-attempt1\summary.json',
      'emule-binary-inventory-summary.json',
      'json-audit-summary.json',
      'ese-live-node-tests-attempt2\summary.json',
      'ese-live-node-tests-attempt3\summary.json',
      'kad6-individual-attempt3\summary.json',
      'kad6-fuzz-asan-attempt3\summary.json',
      'kad6-fuzz-asan-attempt3\stdout.log',
      'kad6-fuzz-asan-attempt4\summary.json',
      'kad6-fuzz-asan-attempt4\stdout.log',
      'kad6-fuzz-asan-attempt5\summary.json',
      'kad6-fuzz-asan-attempt5\stdout.log') $true 'COMPLETE'

Add-Case 'V91-I01' 'BLOCKED' 'T5' `
    'A deterministic incompressible 4 GiB transfer passed with matching SHA-256, an observed WARP IPv6 data socket and no IPv4 socket to the source. It remains non-normative because both profiles ran on H1 and IPv4 was not removed from the host.' `
    @('topology-availability-public.json',
      'i01-exact-incompressible-attempt13\evidence\summary.json',
      'i01-exact-incompressible-attempt13\evidence\fixture-provenance.json',
      'i01-exact-incompressible-attempt13\evidence\REPORT-V91-I01.json') $true 'PARTIAL_COMPLETE'
Add-Case 'V91-I02' 'BLOCKED' 'T5' `
    'An exact-candidate two-hour IPv6 LiveTV run passed: playlist and chunks remained valid, an IPv6 data connection stayed active, no IPv4 fallback occurred, and source/viewer resource monitors passed. Both peers were isolated profiles on H1, so normative T5 remains unavailable.' `
    @('topology-availability-public.json',
      'i02-exact-partial-attempt2\evidence\session.json',
      'i02-exact-partial-attempt2\evidence\route-start.json',
      'i02-exact-partial-attempt2\evidence\live-summary.json',
      'i02-exact-partial-attempt2\evidence\source-summary.json',
      'i02-exact-partial-attempt2\evidence\viewer-summary.json',
      'i02-exact-partial-attempt2\evidence\summary.json',
      'i02-exact-partial-attempt2\evidence\REPORT-V91-I02.json') $true 'PARTIAL_COMPLETE'
Add-Case 'V91-I03' 'BLOCKED' 'T1' `
    'The laptop is reachable but runs eSE 9.0.0-beta.1 and cannot be deployed or controlled with the frozen candidate.' `
    @('topology-availability-public.json')
Add-Case 'V91-I04' 'BLOCKED' 'T1' `
    'AAAA failure with A fallback requires a controllable second node; no exact-candidate T1 pair is available.' `
    @('topology-availability-public.json')
Add-Case 'V91-I05' 'BLOCKED' 'T1' `
    'The inherited IPv4 transfer baseline still requires a controllable second physical node. Two same-host controls (loopback and physical LAN address) were filtered before dialing, so they cannot certify or falsify the T1 peer path.' `
    @('topology-availability-public.json',
      'i05-exact-partial-attempt2\evidence\summary.json',
      'i05-lan-smoke-attempt3\evidence\summary.json') $true 'PARTIAL_INCONCLUSIVE'
Add-Case 'V91-I06' 'BLOCKED' 'T6' `
    'Only H1 is controllable with the exact candidate; María is online but blocked at Windows authentication and has no eSE listener.' `
    @('topology-availability-public.json',
      'topology-recheck.json')
Add-Case 'V91-I07' 'BLOCKED' 'T3' `
    'The hotspot laptop is online, but its installed build is 9.0.0-beta.1; a direct eSE 9.1 connection cannot be truthfully certified.' `
    @('topology-availability-public.json')
Add-Case 'V91-I08' 'BLOCKED' 'T5' `
    'No independent Windows IPv6-only echo endpoint is controllable with the exact candidate.' `
    @('topology-availability-public.json')
Add-Case 'V91-D01' 'BLOCKED' 'T1' `
    'Dual A/AAAA resolution with forced AAAA failure needs the unavailable controllable T1 peer.' `
    @('topology-availability-public.json')

Add-Case 'V91-P01' 'PASS' 'T0/T1' `
    'Three independent SOCKS5 captures contain ATYP=4, the exact 16-byte IPv6 destination, and port 42424.' `
    @('proxy-ipv6-attempt3\evidence\V91-P01-summary.json',
      'proxy-ipv6-attempt3\evidence\V91-PROXY-SUMMARY.json',
      'proxy-ipv6-attempt4\evidence\V91-PROXY-SUMMARY.json',
      'proxy-ipv6-attempt5\evidence\V91-PROXY-SUMMARY.json') $true 'COMPLETE'
Add-Case 'V91-P02' 'PASS' 'T0/T1' `
    'Three independent HTTP proxy captures contain a correctly bracketed IPv6 CONNECT authority and the expected port.' `
    @('proxy-ipv6-attempt3\evidence\V91-P02-summary.json',
      'proxy-ipv6-attempt3\evidence\V91-PROXY-SUMMARY.json',
      'proxy-ipv6-attempt4\evidence\V91-PROXY-SUMMARY.json',
      'proxy-ipv6-attempt5\evidence\V91-PROXY-SUMMARY.json') $true 'COMPLETE'
Add-Case 'V91-P03' 'FAIL' 'T0' `
    'Three independent runs emitted no truncated SOCKS4 connection, but direct_join returned dialed=true instead of explicitly rejecting an IPv6 destination.' `
    @('proxy-ipv6-attempt3\evidence\V91-P03-summary.json',
      'proxy-ipv6-attempt3\evidence\V91-PROXY-SUMMARY.json',
      'proxy-ipv6-attempt4\evidence\V91-PROXY-SUMMARY.json',
      'proxy-ipv6-attempt5\evidence\V91-PROXY-SUMMARY.json') $true 'COMPLETE'

Add-Case 'V91-K01' 'BLOCKED' 'T5' `
    'Kad6-only bootstrap, authenticated routing, publish, and source recovery require a second exact-candidate IPv6-only node.' `
    @('topology-availability-public.json')
Add-Case 'V91-K02' 'BLOCKED' 'T1' `
    'Runtime isolation of Kad2 and Kad6 requires the unavailable controllable T1 peer.' `
    @('topology-availability-public.json')
Add-Case 'V91-K03' 'PASS' 'profiles' `
    'Two completed runs opened a copied Kad6 profile under the exact previous eSE 8.1 binary without reactivating legacy Kad2. Slow shutdown remains a non-gating diagnostic here and is gated by V91-C03.' `
    @('k03-downgrade-attempt3\evidence\V91-K03-SUMMARY.json',
      'k03-downgrade-attempt6\evidence\V91-K03-SUMMARY.json') $true 'COMPLETE'
Add-Case 'V91-K04' 'BLOCKED' 'T1/T5' `
    'Two populated nodes_v6.dat stores and a two-node restart are required; only one exact-candidate node is controllable.' `
    @('topology-availability-public.json')

Add-Case 'V91-C01' 'BLOCKED' 'V1' `
    'The exact candidate transferred 223,394,208 bytes from vanilla 0.70b with matching SHA-256, complete framing, no unexpected opcode pair and only additive HELLO tags allowed by the revised specification. Hyper-V V1 remains unavailable, so this is partial H1 evidence.' `
    @('topology-availability-public.json',
      'c01-exact-partial-attempt6\evidence\summary.json',
      'c01-exact-partial-attempt6\evidence\REPORT-V91-C01.json') $true 'PARTIAL_COMPLETE'
Add-Case 'V91-C02' 'PASS' 'T0' `
    'Eighteen of eighteen rejection scenarios passed across three independent two-round campaigns; rejected surfaces remained closed.' `
    @('consent-matrix-attempt3\evidence\V91-CONSENT-SUMMARY.json',
      'consent-matrix-attempt4\evidence\V91-CONSENT-SUMMARY.json',
      'consent-matrix-attempt5\evidence\V91-CONSENT-SUMMARY.json') $true 'COMPLETE'
Add-Case 'V91-C03' 'FAIL' 'T0/T1' `
    'All six executions across three campaigns failed: shutdown exceeded five seconds and a restart re-enabled accepted NetLab levels despite persisted EseNetLabEnabled=0.' `
    @('consent-matrix-attempt3\evidence\V91-CONSENT-SUMMARY.json',
      'consent-matrix-attempt4\evidence\V91-CONSENT-SUMMARY.json',
      'consent-matrix-attempt5\evidence\V91-CONSENT-SUMMARY.json') $true 'COMPLETE'
Add-Case 'V91-C04' 'PASS' 'T0' `
    'All six executions across three campaigns failed closed with incomplete KRP configuration and opened neither listener nor connection.' `
    @('consent-matrix-attempt3\evidence\V91-CONSENT-SUMMARY.json',
      'consent-matrix-attempt4\evidence\V91-CONSENT-SUMMARY.json',
      'consent-matrix-attempt5\evidence\V91-CONSENT-SUMMARY.json') $true 'COMPLETE'

Add-Case 'V91-S01' 'BLOCKED' 'T5' `
    'Unit coverage retains native 128-bit addresses, but the normative two-endpoint collision injection needs unavailable T5.' `
    @('V91-A01\summary.json',
      'kad6-individual-attempt2\summary.json',
      'kad6-individual-attempt3\summary.json',
      'kad6-fuzz-asan-attempt3\summary.json',
      'kad6-fuzz-asan-attempt4\summary.json',
      'kad6-fuzz-asan-attempt5\summary.json',
      'topology-availability-public.json') $true 'PARTIAL_COMPLETE'
Add-Case 'V91-S02' 'BLOCKED' 'T5' `
    'Record and epoch unit suites pass, but temporal-address reuse and credit isolation require unavailable T5.' `
    @('V91-A01\summary.json',
      'kad6-individual-attempt2\summary.json',
      'kad6-individual-attempt3\summary.json',
      'kad6-fuzz-asan-attempt3\summary.json',
      'kad6-fuzz-asan-attempt4\summary.json',
      'kad6-fuzz-asan-attempt5\summary.json',
      'topology-availability-public.json') $true 'PARTIAL_COMPLETE'
Add-Case 'V91-S03' 'BLOCKED' 'T1/T5' `
    'Front-door challenge unit gates pass, but packet capture against an unverified remote endpoint requires unavailable T1/T5.' `
    @('V91-A01\summary.json',
      'kad6-individual-attempt2\summary.json',
      'kad6-individual-attempt3\summary.json',
      'kad6-fuzz-asan-attempt3\summary.json',
      'kad6-fuzz-asan-attempt4\summary.json',
      'kad6-fuzz-asan-attempt5\summary.json',
      'topology-availability-public.json') $true 'PARTIAL_COMPLETE'
Add-Case 'V91-R01' 'BLOCKED' 'T3' `
    'The laptop cannot be controlled or upgraded from 9.0.0-beta.1, so LAN-to-hotspot handover cannot run on the exact candidate.' `
    @('topology-availability-public.json')
Add-Case 'V91-O01' 'BLOCKED' 'T1/T5' `
    'A 5.5-hour exact-candidate continuation passed Live integrity and source/viewer resource gates: no disconnect or IPv4 fallback, stable duplicate ratio, and less than 2 MiB working-set growth per process. The mandatory twelve-hour T1/T5 duration and independent node remain unavailable.' `
    @('topology-availability-public.json',
      'o01-exact-partial-attempt1\evidence\session.json',
      'o01-exact-partial-attempt1\evidence\live-summary.json',
      'o01-exact-partial-attempt1\evidence\source-summary.json',
      'o01-exact-partial-attempt1\evidence\viewer-summary.json',
      'o01-exact-partial-attempt1\evidence\summary.json',
      'o01-exact-partial-attempt1\evidence\REPORT-V91-O01.json') $true 'PARTIAL_COMPLETE'

$expectedIds = @(
    'V91-A01',
    'V91-I01', 'V91-I02', 'V91-I03', 'V91-I04', 'V91-I05', 'V91-I06',
    'V91-I07', 'V91-I08', 'V91-D01',
    'V91-P01', 'V91-P02', 'V91-P03',
    'V91-K01', 'V91-K02', 'V91-K03', 'V91-K04',
    'V91-C01', 'V91-C02', 'V91-C03', 'V91-C04',
    'V91-S01', 'V91-S02', 'V91-S03', 'V91-R01', 'V91-O01'
)
$actualIds = @($cases | ForEach-Object id)
if ($actualIds.Count -ne 26 -or
    (Compare-Object -ReferenceObject $expectedIds -DifferenceObject $actualIds)) {
    throw 'The V91 campaign ledger does not contain the exact mandatory 26-case set.'
}
if (@($actualIds | Group-Object | Where-Object Count -ne 1).Count -ne 0) {
    throw 'The V91 campaign ledger contains duplicate case IDs.'
}

$counts = [ordered]@{
    total = $cases.Count
    pass = @($cases | Where-Object status -eq 'PASS').Count
    fail = @($cases | Where-Object status -eq 'FAIL').Count
    blocked = @($cases | Where-Object status -eq 'BLOCKED').Count
    executed_formal = @($cases | Where-Object { $_.executed -and $_.status -ne 'BLOCKED' }).Count
    executed_partial = @($cases | Where-Object { $_.executed -and $_.status -eq 'BLOCKED' }).Count
}
$ledger = [ordered]@{
    schema = 'ese.v91.campaign-ledger/v1'
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    candidate_commit = $candidateCommit
    candidate_binary_sha256 = $candidateSha256
    normative_source = 'docs/V9_RELEASE_SPECIFICATION.md section 8.6'
    counts = $counts
    gate_decision = if ($counts.fail -eq 0 -and $counts.blocked -eq 0) {
        'GO'
    } else {
        'NO_GO'
    }
    cases = @($cases)
}

$output = Join-Path $root 'V91-CASE-LEDGER.json'
$ledger | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $output -Encoding utf8
Write-Host "V91 ledger written: $output"
Write-Host "PASS=$($counts.pass) FAIL=$($counts.fail) BLOCKED=$($counts.blocked)"
