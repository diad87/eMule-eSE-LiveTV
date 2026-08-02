[CmdletBinding()]
param(
    [string]$RepoRoot = '',
    [string]$NodePath = '',
    [string]$OutputRoot = '',
    [string]$PhysicalEvidencePath = ''
)

$ErrorActionPreference = 'Stop'

if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$repoPrefix = $RepoRoot.TrimEnd([char[]]@('\', '/')) + '\'
$gatewayRoot = Join-Path $PSScriptRoot 'nat_gateway'
$coveragePath = Join-Path $gatewayRoot 'wp0_coverage.json'
$temporaryOutput = -not $OutputRoot
$requiredMinimumNodeTests = 295
$requiredCoverageIds = @(
    'SCENARIO_SCHEMA_AND_LOADER',
    'NATPMP_CODEC',
    'PCP_CODEC',
    'UPNP_SUCCESS',
    'PCP_SUCCESS',
    'NATPMP_SUCCESS',
    'SLOW_OR_LOST_RESPONSE',
    'ALTERNATE_EXTERNAL_PORT',
    'SHORT_LEASE',
    'EPOCH_RESTART',
    'PRIVATE_OR_CGNAT_EXTERNAL',
    'PORT_COLLISION',
    'RENEWAL_REJECTED',
    'MAPPING_DISAPPEARED',
    'DOUBLE_NAT_FIRST_LAYER',
    'DOUBLE_NAT_POLICY',
    'TWO_CLIENT_OWNERSHIP',
    'HIGHID_EVIDENCE',
    'HOSTILE_CORPUS',
    'WEBSERVER_PRIVACY',
    'ADDRESS_POLICY',
    'NETWORK_SIGNATURE',
    'NETWORK_CHANGE',
    'MAPPING_RECOVERY',
    'PCP_UPSTREAM',
    'IPV6_PRIORITY',
    'HYPERV_PURE_PLAN',
    'STATE_CAPTURE',
    'CANONICAL_REPORT',
    'PUBLIC_SANITIZATION'
)

if (-not $NodePath) {
    $NodePath = (Get-Command node.exe -ErrorAction Stop).Source
}
$NodePath = (Resolve-Path -LiteralPath $NodePath).Path

if (-not $OutputRoot) {
    $OutputRoot = Join-Path ([IO.Path]::GetTempPath()) (
        'eSE-v92-t8-wp0-' + [Guid]::NewGuid().ToString('N'))
}
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
if (Test-Path -LiteralPath $OutputRoot) {
    throw "OutputRoot already exists; refusing to mix evidence: $OutputRoot"
}
$null = New-Item -ItemType Directory -Path $OutputRoot

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-TapCount {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $match = [regex]::Match(
        $Text, "(?m)^# $([regex]::Escape($Name)) ([0-9]+)\s*$")
    if (-not $match.Success) {
        throw "Node TAP summary is missing '# $Name'"
    }
    return [int]$match.Groups[1].Value
}

function Assert-PublicReport {
    param([Parameter(Mandatory = $true)][string]$Json)
    $forbidden = @(
        '(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?![0-9])',
        '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
        '(?i)\b[a-z]:\\',
        '\\\\[^\\"]+\\'
    )
    foreach ($pattern in $forbidden) {
        if ($Json -match $pattern) {
            throw 'Canonical WP0 report contains a forbidden host or network identifier'
        }
    }
}

function Test-ExactTrueProperty {
    param(
        [Parameter(Mandatory = $true)][object]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $property = $Object.PSObject.Properties[$Name]
    return (
        $null -ne $property -and
        $property.Value -is [bool] -and
        $property.Value -eq $true
    )
}

try {
    $coverage = Get-Content -LiteralPath $coveragePath -Raw |
        ConvertFrom-Json
    if ([string]$coverage.schema -ne 'ese.v92.t8-wp0-coverage/v1' -or
        $coverage.minimum_node_tests -isnot [int] -or
        [int]$coverage.minimum_node_tests -ne $requiredMinimumNodeTests -or
        @($coverage.checks).Count -ne $requiredCoverageIds.Count) {
        throw 'Invalid T8 WP0 coverage manifest'
    }

    $coverageIds = [System.Collections.Generic.List[string]]::new()
    $seenCoverageIds = @{}
    foreach ($check in @($coverage.checks)) {
        $id = [string]$check.id
        if ($id -notmatch '^[A-Z][A-Z0-9_]{2,63}$' -or
            $seenCoverageIds.ContainsKey($id) -or
            @($check.evidence).Count -lt 1) {
            throw "Invalid or duplicate T8 WP0 coverage check: $id"
        }
        $seenCoverageIds[$id] = $true
        foreach ($item in @($check.evidence)) {
            $relative = [string]$item.file
            $needle = [string]$item.contains
            if (-not $relative -or -not $needle -or
                [IO.Path]::IsPathRooted($relative) -or
                $relative -match '(^|[\\/])\.\.([\\/]|$)') {
                throw "Unsafe T8 WP0 evidence reference in $id"
            }
            $full = [IO.Path]::GetFullPath((Join-Path $RepoRoot $relative))
            if (-not $full.StartsWith(
                    $repoPrefix, [StringComparison]::OrdinalIgnoreCase) -or
                -not (Test-Path -LiteralPath $full -PathType Leaf)) {
                throw "Missing T8 WP0 evidence source for $id"
            }
            $source = [IO.File]::ReadAllText($full)
            if ($source.IndexOf(
                    $needle, [StringComparison]::Ordinal) -lt 0) {
                throw "T8 WP0 evidence assertion is stale for $id"
            }
        }
        $coverageIds.Add($id)
    }
    for ($index = 0; $index -lt $requiredCoverageIds.Count; $index++) {
        if ($coverageIds[$index] -cne $requiredCoverageIds[$index]) {
            throw 'T8 WP0 coverage contract is missing or reordered'
        }
    }

    $nodeVersion = @(& $NodePath --version 2>&1)
    if ($LASTEXITCODE -ne 0 -or
        ($nodeVersion -join '') -notmatch '^v22\.') {
        throw 'T8 WP0 requires Node.js 22.x'
    }
    if (-not (Test-Path -LiteralPath (
            Join-Path $gatewayRoot 'node_modules\ajv') -PathType Container)) {
        throw 'T8 WP0 dependencies are missing; run npm ci in tools/lab/nat_gateway'
    }

    Push-Location $gatewayRoot
    try {
        $oldPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $nodeOutput = @(& $NodePath --test 2>&1)
        $nodeExit = $LASTEXITCODE
        $ErrorActionPreference = $oldPreference
    } finally {
        Pop-Location
    }
    $nodeOutput | ForEach-Object { Write-Host $_ }
    $nodeText = ($nodeOutput | ForEach-Object { [string]$_ }) -join "`n"
    $nodeTests = Get-TapCount -Text $nodeText -Name 'tests'
    $nodePassed = Get-TapCount -Text $nodeText -Name 'pass'
    $nodeFailed = Get-TapCount -Text $nodeText -Name 'fail'
    $nodeSkipped = Get-TapCount -Text $nodeText -Name 'skipped'
    $nodeVerdict = (
        $nodeExit -eq 0 -and
        $nodeFailed -eq 0 -and
        $nodeTests -ge [int]$coverage.minimum_node_tests -and
        ($nodePassed + $nodeSkipped) -eq $nodeTests
    )

    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $l04Output = @(
            & cmd.exe /d /c (
                '"' + (Join-Path $RepoRoot 'libnatmap\make.bat') + '"') 2>&1)
        $l04BuildExit = $LASTEXITCODE
        $l04HostOutput = @(
            & python.exe (
                Join-Path $RepoRoot 'tests\test_v92_l04_two_instances.py') 2>&1)
        $l04HostExit = $LASTEXITCODE
        $l05HostOutput = @(
            & python.exe (
                Join-Path $RepoRoot 'tests\test_v92_l05_false_highid.py') 2>&1)
        $l05HostExit = $LASTEXITCODE
        $l06HostOutput = @(
            & python.exe (
                Join-Path $RepoRoot 'tests\test_v92_l06_double_evidence.py') 2>&1)
        $l06HostExit = $LASTEXITCODE
        $l07HostOutput = @(
            & python.exe (
                Join-Path $RepoRoot 'tests\test_v92_l07_hostile_corpus.py') 2>&1)
        $l07HostExit = $LASTEXITCODE
        $l08HostOutput = @(
            & python.exe (
                Join-Path $RepoRoot 'tests\test_v92_l08_webserver_privacy.py') 2>&1)
        $l08HostExit = $LASTEXITCODE
        $l08RuntimeOutput = @(
            & powershell.exe -NoProfile -NonInteractive -File (
                Join-Path $RepoRoot 'tests\test_v92_l08_privacy_runtime.ps1'
            ) -RepoRoot $RepoRoot -NodePath $NodePath 2>&1)
        $l08RuntimeExit = $LASTEXITCODE
        $m01HostOutput = @(
            & python.exe (
                Join-Path $RepoRoot 'tests\test_v92_m01_address_policy.py') 2>&1)
        $m01HostExit = $LASTEXITCODE
        $m02HostOutput = @(
            & python.exe (
                Join-Path $RepoRoot 'tests\test_v92_m02_double_nat.py') 2>&1)
        $m02HostExit = $LASTEXITCODE
        $m03HostOutput = @(
            & python.exe (
                Join-Path $RepoRoot 'tests\test_v92_m03_network_signature.py') 2>&1)
        $m03HostExit = $LASTEXITCODE
        $m04HostOutput = @(
            & python.exe (
                Join-Path $RepoRoot 'tests\test_v92_m04_network_change.py') 2>&1)
        $m04HostExit = $LASTEXITCODE
        $m05HostOutput = @(
            & python.exe (
                Join-Path $RepoRoot 'tests\test_v92_m05_backoff.py') 2>&1)
        $m05HostExit = $LASTEXITCODE
        $m06HostOutput = @(
            & python.exe (
                Join-Path $RepoRoot 'tests\test_v92_m06_ipv6_priority.py') 2>&1)
        $m06HostExit = $LASTEXITCODE
        $mx03HostOutput = @(
            & python.exe (
                Join-Path $RepoRoot 'tests\test_v92_mx03_pcp_upstream.py') 2>&1)
        $mx03HostExit = $LASTEXITCODE
        $mx04HostOutput = @(
            & python.exe (
                Join-Path $RepoRoot 'tests\test_v92_mx04_ipv6_scope.py') 2>&1)
        $mx04HostExit = $LASTEXITCODE
        $mx05HostOutput = @(
            & python.exe (
                Join-Path $RepoRoot 'tests\test_v92_mx05_handoff.py') 2>&1)
        $mx05HostExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $oldPreference
    }
    $l04Output | ForEach-Object { Write-Host $_ }
    $l04HostOutput | ForEach-Object { Write-Host $_ }
    $l05HostOutput | ForEach-Object { Write-Host $_ }
    $l06HostOutput | ForEach-Object { Write-Host $_ }
    $l07HostOutput | ForEach-Object { Write-Host $_ }
    $l08HostOutput | ForEach-Object { Write-Host $_ }
    $l08RuntimeOutput | ForEach-Object { Write-Host $_ }
    $m01HostOutput | ForEach-Object { Write-Host $_ }
    $m02HostOutput | ForEach-Object { Write-Host $_ }
    $m03HostOutput | ForEach-Object { Write-Host $_ }
    $m04HostOutput | ForEach-Object { Write-Host $_ }
    $m05HostOutput | ForEach-Object { Write-Host $_ }
    $m06HostOutput | ForEach-Object { Write-Host $_ }
    $mx03HostOutput | ForEach-Object { Write-Host $_ }
    $mx04HostOutput | ForEach-Object { Write-Host $_ }
    $mx05HostOutput | ForEach-Object { Write-Host $_ }
    $l04Text = ($l04Output | ForEach-Object { [string]$_ }) -join "`n"
    $l04HostText = (
        $l04HostOutput | ForEach-Object { [string]$_ }) -join "`n"
    $l05HostText = (
        $l05HostOutput | ForEach-Object { [string]$_ }) -join "`n"
    $l06HostText = (
        $l06HostOutput | ForEach-Object { [string]$_ }) -join "`n"
    $l07HostText = (
        $l07HostOutput | ForEach-Object { [string]$_ }) -join "`n"
    $l08HostText = (
        $l08HostOutput | ForEach-Object { [string]$_ }) -join "`n"
    $l08RuntimeText = (
        $l08RuntimeOutput | ForEach-Object { [string]$_ }) -join "`n"
    $m01HostText = (
        $m01HostOutput | ForEach-Object { [string]$_ }) -join "`n"
    $m02HostText = (
        $m02HostOutput | ForEach-Object { [string]$_ }) -join "`n"
    $m03HostText = (
        $m03HostOutput | ForEach-Object { [string]$_ }) -join "`n"
    $m04HostText = (
        $m04HostOutput | ForEach-Object { [string]$_ }) -join "`n"
    $m05HostText = (
        $m05HostOutput | ForEach-Object { [string]$_ }) -join "`n"
    $m06HostText = (
        $m06HostOutput | ForEach-Object { [string]$_ }) -join "`n"
    $mx03HostText = (
        $mx03HostOutput | ForEach-Object { [string]$_ }) -join "`n"
    $mx04HostText = (
        $mx04HostOutput | ForEach-Object { [string]$_ }) -join "`n"
    $mx05HostText = (
        $mx05HostOutput | ForEach-Object { [string]$_ }) -join "`n"
    $l04Verdict = (
        $l04BuildExit -eq 0 -and
        $l04HostExit -eq 0 -and
        $l04Text -match 'two-instance T8: [0-9]+ checks, 0 failures' -and
        $l04HostText -match '(?m)^OK\s*$'
    )
    $l05Verdict = (
        $l04BuildExit -eq 0 -and
        $l05HostExit -eq 0 -and
        $l04Text -match 'false HighID L05: [0-9]+ checks, 0 failures' -and
        $l05HostText -match '(?m)^OK\s*$'
    )
    $l06Verdict = (
        $l04BuildExit -eq 0 -and
        $l06HostExit -eq 0 -and
        $l04Text -match 'double evidence L06: 45 checks, 0 failures' -and
        $l06HostText -match '(?m)^OK\s*$'
    )
    $l07Verdict = (
        $l04BuildExit -eq 0 -and
        $l07HostExit -eq 0 -and
        $l04Text -match 'hostile corpus L07: 2245 checks, 0 failures' -and
        $l07HostText -match '(?m)^OK\s*$'
    )
    $l08Verdict = (
        $l08HostExit -eq 0 -and
        $l08HostText -match 'Ran 7 tests' -and
        $l08HostText -match '(?m)^OK\s*$' -and
        $l08RuntimeExit -eq 0 -and
        $l08RuntimeText -match (
            'L08_RUNTIME_PASS node=2 report=1 zip_positive=1 ' +
            'zip_negative=1 command_graph=4'
        )
    )
    $m01NativeMatch = [regex]::Match(
        $l04Text, 'test_address_policy: (\d+) checks, 0 failures')
    $m01NativeChecks = if ($m01NativeMatch.Success) {
        [int]$m01NativeMatch.Groups[1].Value
    } else {
        0
    }
    $m01Verdict = (
        $l04BuildExit -eq 0 -and
        $m01HostExit -eq 0 -and
        $m01NativeChecks -ge 260 -and
        $m01HostText -match 'Ran 6 tests' -and
        $m01HostText -match '(?m)^OK\s*$'
    )
    $m02NativeMatch = [regex]::Match(
        $l04Text, 'test_nat_chain: (\d+) checks, 0 failures')
    $m02NativeChecks = if ($m02NativeMatch.Success) {
        [int]$m02NativeMatch.Groups[1].Value
    } else {
        0
    }
    $m02Verdict = (
        $l04BuildExit -eq 0 -and
        $m02HostExit -eq 0 -and
        $m02NativeChecks -ge 57 -and
        $m02HostText -match 'Ran 8 tests' -and
        $m02HostText -match '(?m)^OK\s*$'
    )
    $m03NativeMatch = [regex]::Match(
        $l04Text, 'test_network_signature: (59) checks, 0 failures')
    $m03NativeChecks = if ($m03NativeMatch.Success) {
        [int]$m03NativeMatch.Groups[1].Value
    } else {
        0
    }
    $m03Verdict = (
        $l04BuildExit -eq 0 -and
        $m03HostExit -eq 0 -and
        $m03NativeChecks -eq 59 -and
        $m03HostText -match 'Ran 7 tests' -and
        $m03HostText -match '(?m)^OK\s*$'
    )
    $m04NativeMatch = [regex]::Match(
        $l04Text, 'test_network_change: (71) checks, 0 failures')
    $m04NativeChecks = if ($m04NativeMatch.Success) {
        [int]$m04NativeMatch.Groups[1].Value
    } else {
        0
    }
    $m04Verdict = (
        $l04BuildExit -eq 0 -and
        $m04HostExit -eq 0 -and
        $m04NativeChecks -eq 71 -and
        $m04HostText -match 'Ran 7 tests' -and
        $m04HostText -match '(?m)^OK\s*$'
    )
    $m05NativeMatch = [regex]::Match(
        $l04Text, 'test_mapping_recovery: (65) checks, 0 failures')
    $m05NativeChecks = if ($m05NativeMatch.Success) {
        [int]$m05NativeMatch.Groups[1].Value
    } else {
        0
    }
    $m05Verdict = (
        $l04BuildExit -eq 0 -and
        $m05HostExit -eq 0 -and
        $m05NativeChecks -eq 65 -and
        $m05HostText -match 'Ran 8 tests' -and
        $m05HostText -match '(?m)^OK\s*$'
    )
    $mx03NativeMatch = [regex]::Match(
        $l04Text, 'test_pcp_upstream_policy: (156) checks, 0 failures')
    $mx03NativeChecks = if ($mx03NativeMatch.Success) {
        [int]$mx03NativeMatch.Groups[1].Value
    } else {
        0
    }
    $mx03Verdict = (
        $l04BuildExit -eq 0 -and
        $mx03HostExit -eq 0 -and
        $mx03NativeChecks -eq 156 -and
        $mx03HostText -match 'Ran 23 tests' -and
        $mx03HostText -match '(?m)^OK\s*$'
    )
    $mx04NativeMatch = [regex]::Match(
        $l04Text, 'test_ipv6_scope_policy: (92) checks, 0 failures')
    $mx04NativeChecks = if ($mx04NativeMatch.Success) {
        [int]$mx04NativeMatch.Groups[1].Value
    } else {
        0
    }
    $mx04Verdict = (
        $l04BuildExit -eq 0 -and
        $mx04HostExit -eq 0 -and
        $mx04NativeChecks -eq 92 -and
        $mx04HostText -match 'Ran 13 tests' -and
        $mx04HostText -match '(?m)^OK\s*$'
    )
    $mx05Verdict = (
        $mx05HostExit -eq 0 -and
        $mx05HostText -match 'Ran 11 tests' -and
        $mx05HostText -match '(?m)^OK\s*$'
    )
    $m06NativeMatch = [regex]::Match(
        $l04Text,
        'test_direct_route_selection: (153) checks, 0 failures')
    $m06NativeChecks = if ($m06NativeMatch.Success) {
        [int]$m06NativeMatch.Groups[1].Value
    } else {
        0
    }
    $m06Verdict = (
        $l04BuildExit -eq 0 -and
        $m06HostExit -eq 0 -and
        $m06NativeChecks -eq 153 -and
        $m06HostText -match 'Ran 14 tests' -and
        $m06HostText -match '(?m)^OK\s*$'
    )

    $hyperVOutput = @()
    $hyperVVerdict = $true
    try {
        $hyperVOutput = @(
            & (Join-Path $PSScriptRoot 'test_t8_hyperv_plan.ps1') 2>&1)
    } catch {
        $hyperVVerdict = $false
        $hyperVOutput = @($_.Exception.Message)
    }
    $hyperVOutput | ForEach-Object { Write-Host $_ }
    if (-not (@($hyperVOutput | ForEach-Object {
                    [string]$_
                }) -ccontains 'T8 Hyper-V pure plan tests PASS')) {
        $hyperVVerdict = $false
    }

    $physicalMode = 'DEGRADED'
    $physicalReason = 'PHYSICAL_EVIDENCE_NOT_REQUIRED_BY_PURE_GATE'
    $physicalHash = $null
    if ($PhysicalEvidencePath) {
        $physicalFull = (Resolve-Path -LiteralPath $PhysicalEvidencePath).Path
        $physical = Get-Content -LiteralPath $physicalFull -Raw |
            ConvertFrom-Json
        if ([string]$physical.schema -ne
                'ese.v92.t8-route-live-test/v1' -or
            [string]$physical.verdict -ne 'PASS' -or
            -not (Test-ExactTrueProperty -Object $physical `
                -Name 'mapper_reached_t8_gateway') -or
            -not (Test-ExactTrueProperty -Object $physical `
                -Name 'data_avoided_tailscale') -or
            -not (Test-ExactTrueProperty -Object $physical `
                -Name 'dns_proxy_neutral') -or
            -not (Test-ExactTrueProperty -Object $physical `
                -Name 'baseline_restored') -or
            [string]$physical.mapper_interface_id -notmatch
                '^[a-f0-9]{12}$' -or
            [string]$physical.mapper_interface_id -cne
                [string]$physical.data_interface_id -or
            [string]$physical.final_phase -ne 'TORN_DOWN') {
            throw 'Physical T8 evidence is not a complete safe PASS'
        }
        $physicalMode = 'PASS'
        $physicalReason = 'VERIFIED_BY_CONTENT_AND_SHA256'
        $physicalHash = Get-Sha256 -Path $physicalFull
    }

    $overallPass = (
        $nodeVerdict -and
        $l04Verdict -and
        $l05Verdict -and
        $l06Verdict -and
        $l07Verdict -and
        $l08Verdict -and
        $m01Verdict -and
        $m02Verdict -and
        $m03Verdict -and
        $m04Verdict -and
        $m05Verdict -and
        $mx03Verdict -and
        $mx04Verdict -and
        $mx05Verdict -and
        $m06Verdict -and
        $hyperVVerdict -and
        $coverageIds.Count -eq $requiredCoverageIds.Count
    )
    $report = [ordered]@{
        schema = 'ese.v92.t8-wp0-report/v1'
        verdict = if ($overallPass) { 'PASS' } else { 'FAIL' }
        generated_at_utc = [DateTime]::UtcNow.ToString('o')
        execution = [ordered]@{
            privilege_required = $false
            external_router_required = $false
            hyperv_physical_mode = $physicalMode
            hyperv_physical_reason = $physicalReason
        }
        node_suite = [ordered]@{
            verdict = if ($nodeVerdict) { 'PASS' } else { 'FAIL' }
            tests = $nodeTests
            passed = $nodePassed
            failed = $nodeFailed
            skipped = $nodeSkipped
        }
        hyperv_pure_plan = [ordered]@{
            verdict = if ($hyperVVerdict) { 'PASS' } else { 'FAIL' }
        }
        l04_two_instance = [ordered]@{
            verdict = if ($l04Verdict) { 'PASS' } else { 'FAIL' }
            physical_mutation = $false
        }
        l05_false_highid = [ordered]@{
            verdict = if ($l05Verdict) { 'PASS' } else { 'FAIL' }
            physical_mutation = $false
        }
        l06_double_evidence = [ordered]@{
            verdict = if ($l06Verdict) { 'PASS' } else { 'FAIL' }
            physical_mutation = $false
        }
        l07_hostile_corpus = [ordered]@{
            verdict = if ($l07Verdict) { 'PASS' } else { 'FAIL' }
            physical_mutation = $false
            exhaustive_sizes = 1102
        }
        l08_webserver_privacy = [ordered]@{
            verdict = if ($l08Verdict) { 'PASS' } else { 'FAIL' }
            physical_mutation = $false
            default_bind = 'loopback'
            router_mapping = $false
            runtime_privacy_projection = $true
            runtime_zip_tamper_rejected = $true
            noninteractive_command_graph = $true
        }
        m01_address_policy = [ordered]@{
            verdict = if ($m01Verdict) { 'PASS' } else { 'FAIL' }
            physical_mutation = $false
            native_checks = $m01NativeChecks
            origin_independent = $true
            scoped_private_exception = $true
        }
        m02_double_nat = [ordered]@{
            verdict = if ($m02Verdict) { 'PASS' } else { 'FAIL' }
            physical_mutation = $false
            native_checks = $m02NativeChecks
            authorized_evidence_only = $true
            maximum_layers = 2
            arbitrary_probe = $false
        }
        m03_network_signature = [ordered]@{
            verdict = if ($m03Verdict) { 'PASS' } else { 'FAIL' }
            physical_mutation = $false
            native_checks = $m03NativeChecks
            exact_identity = $true
            volatile_fields = $false
            compartment_aware = $true
        }
        m04_network_change = [ordered]@{
            verdict = if ($m04Verdict) { 'PASS' } else { 'FAIL' }
            physical_mutation = $false
            native_checks = $m04NativeChecks
            exact_generation_advance = $true
            stale_callback_fenced = $true
            rediscovery_requires_valid_generation = $true
        }
        m05_mapping_recovery = [ordered]@{
            verdict = if ($m05Verdict) { 'PASS' } else { 'FAIL' }
            physical_mutation = $false
            native_checks = $m05NativeChecks
            maximum_rounds = 6
            success_resets_backoff = $true
            network_change_reset_is_generation_bound = $true
        }
        mx03_pcp_upstream = [ordered]@{
            verdict = if ($mx03Verdict) { 'PASS' } else { 'FAIL' }
            physical_mutation = $false
            native_checks = $mx03NativeChecks
            upstream_authorization = 'M02 typed evidence only'
            cpe_local_map_is_global_proof = $false
        }
        mx04_ipv6_scope = [ordered]@{
            verdict = if ($mx04Verdict) { 'PASS' } else { 'FAIL' }
            physical_mutation = $false
            native_checks = $mx04NativeChecks
            global_requires_exact_firewall_evidence = $true
            same_lan_requires_on_link_os_route = $true
            tcp_proof_authorizes_udp = $false
            unsanitized_reporting = $false
        }
        mx05_v92_to_v93_handoff = [ordered]@{
            verdict = if ($mx05Verdict) { 'PASS' } else { 'FAIL' }
            physical_mutation = $false
            host_checks = 11
            schema_and_artifacts_hashed = [bool]$mx05Verdict
            stale_callbacks_fenced = [bool]$mx05Verdict
            current_events_applied = [bool]$mx05Verdict
            excluded_features_verified = [bool]$mx05Verdict
            actionable_endpoints_exported = if ($mx05Verdict) {
                $false
            } else {
                $null
            }
        }
        m06_ipv6_priority = [ordered]@{
            verdict = if ($m06Verdict) { 'PASS' } else { 'FAIL' }
            physical_mutation = $false
            native_checks = $m06NativeChecks
            verified_ipv6_first = $true
            candidates_never_selected = $true
            classic_fallback_preserved = $true
            direct_ipv4_endpoint_bound = $true
            stale_listener_backlog_fenced = $true
        }
        coverage = [ordered]@{
            schema_sha256 = Get-Sha256 -Path (
                Join-Path $gatewayRoot 'scenario.schema.json')
            manifest_sha256 = Get-Sha256 -Path $coveragePath
            check_count = $coverageIds.Count
            checks = @($coverageIds)
        }
        physical_evidence = [ordered]@{
            supplied = [bool]$PhysicalEvidencePath
            sha256 = $physicalHash
        }
        privacy = [ordered]@{
            projection = 'sanitized'
            raw_addresses = $false
            raw_host_paths = $false
            raw_adapter_or_host_ids = $false
        }
    }

    $json = $report | ConvertTo-Json -Depth 8 -Compress
    Assert-PublicReport -Json $json
    $reportPath = Join-Path $OutputRoot 'wp0-report.json'
    $utf8 = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($reportPath, $json + "`n", $utf8)
    $reportHash = Get-Sha256 -Path $reportPath
    [IO.File]::WriteAllText(
        (Join-Path $OutputRoot 'wp0-report.sha256'),
        "$reportHash  wp0-report.json`n", $utf8)

    if (-not $overallPass) {
        throw 'T8 WP0 gate failed; inspect the emitted canonical report'
    }
    Write-Host "T8 WP0 autotest PASS: $reportPath" -ForegroundColor Green
} finally {
    if ($temporaryOutput -and
        (Test-Path -LiteralPath $OutputRoot -PathType Container)) {
        $tempRoot = [IO.Path]::GetFullPath(
            [IO.Path]::GetTempPath()).TrimEnd([char[]]@('\', '/'))
        $outputParent = [IO.Path]::GetFullPath(
            (Split-Path -Parent $OutputRoot)).TrimEnd([char[]]@('\', '/'))
        $outputLeaf = Split-Path -Leaf $OutputRoot
        if ($outputParent -ne $tempRoot -or
            -not $outputLeaf.StartsWith('eSE-v92-t8-wp0-')) {
            throw "Refusing unsafe T8 WP0 cleanup: $OutputRoot"
        }
        Remove-Item -LiteralPath $OutputRoot -Recurse -Force
    }
}
