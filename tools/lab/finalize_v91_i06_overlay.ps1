<#
.SYNOPSIS
Adjudicates a completed V91-I06 Tailscale/DERP overlay transfer.

.DESCRIPTION
Validates the exact candidate package, the isolated viewer session and route,
every LiveTV soak sample, and explicit T6/Tailscale/DERP path metadata. A
formal, identity-bound PASS JSON is written only when every gate succeeds.

This case proves remote IPv6 transport over an overlay. It does not prove
native/direct public IPv6 reachability.

.PARAMETER CandidatePackage
Path to the extracted exact-candidate package.

.PARAMETER Commit
Full 40-character commit expected in BUILD_INFO.txt and all identity evidence.

.PARAMETER OutputRoot
Root created by start_v91_i06_isolated_viewer.ps1.

.PARAMETER SourceReadyCaptureRelativePath
Private READY capture path relative to OutputRoot. The finalizer hashes it but
never embeds its path or contents in the public result.

.PARAMETER OutFile
Optional path for the sanitized, self-contained formal result. The default is
OutputRoot\evidence\V91-I06-PASS.json.

.PARAMETER LedgerOutFile
Optional path for the private ledger companion. This companion contains only
the relative paths needed by write_v91_campaign_ledger.ps1 and must not be
published. The default is OutputRoot\evidence\V91-I06-LEDGER-RESULT.json.

.PARAMETER Force
Allows replacement of an existing formal result after all evidence is
revalidated. Without this switch an existing result is never overwritten.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CandidatePackage,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$Commit,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [string]$SourceReadyCaptureRelativePath =
        'evidence\source-ready-private.jpg',
    [string]$OutFile = '',
    [string]$LedgerOutFile = '',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

function Get-I06RequiredProperty {
    param(
        [AllowNull()]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if ($null -eq $Object) {
        throw "$Context is missing."
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        throw "$Context is missing required property '$Name'."
    }
    return $property.Value
}

function Assert-I06ExactProperties {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string[]]$Allowed,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $actual = @($Object.PSObject.Properties.Name)
    $unexpected = @($actual | Where-Object { $_ -notin $Allowed })
    $missing = @($Allowed | Where-Object { $_ -notin $actual })
    if ($unexpected.Count -gt 0 -or $missing.Count -gt 0) {
        throw (
            "$Context property set is not canonical; unexpected=[" +
            "$($unexpected -join ', ')] missing=[$($missing -join ', ')]."
        )
    }
}

function Assert-I06Equal {
    param(
        [AllowNull()]$Actual,
        [AllowNull()]$Expected,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if ($Actual -ne $Expected) {
        throw "$Context mismatch: actual='$Actual' expected='$Expected'."
    }
}

function Assert-I06Boolean {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory = $true)][bool]$Expected,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if ($Value -isnot [bool] -or [bool]$Value -ne $Expected) {
        throw "$Context must be the JSON boolean $($Expected.ToString().ToLowerInvariant())."
    }
}

function ConvertTo-I06DateTimeOffset {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $parsed = [DateTimeOffset]::MinValue
    if ($Value -isnot [string] -or
        -not [DateTimeOffset]::TryParse(
            [string]$Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$parsed)) {
        throw "$Context is not a valid round-trip timestamp."
    }
    return $parsed
}

function Assert-I06CandidateIdentity {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)]$Candidate,
        [Parameter(Mandatory = $true)][string]$Context,
        [string]$CommitProperty = 'candidate_commit',
        [string]$BinaryProperty = 'candidate_binary_sha256',
        [string]$ServerProperty = 'candidate_ese_server_sha256',
        [string]$BuildInfoProperty = 'candidate_build_info_sha256'
    )

    $actualCommit = [string](Get-I06RequiredProperty -Object $Object `
        -Name $CommitProperty -Context $Context)
    $actualBinary = [string](Get-I06RequiredProperty -Object $Object `
        -Name $BinaryProperty -Context $Context)
    $actualServer = [string](Get-I06RequiredProperty -Object $Object `
        -Name $ServerProperty -Context $Context)
    $actualBuildInfo = [string](Get-I06RequiredProperty -Object $Object `
        -Name $BuildInfoProperty -Context $Context)

    Assert-I06Equal -Actual $actualCommit.ToLowerInvariant() `
        -Expected $Candidate.commit -Context "$Context commit"
    Assert-I06Equal -Actual $actualBinary.ToLowerInvariant() `
        -Expected $Candidate.emule_sha256 -Context "$Context emule.exe hash"
    Assert-I06Equal -Actual $actualServer.ToLowerInvariant() `
        -Expected $Candidate.ese_server_sha256 `
        -Context "$Context ese-server.exe hash"
    Assert-I06Equal -Actual $actualBuildInfo.ToLowerInvariant() `
        -Expected $Candidate.build_info_sha256 `
        -Context "$Context BUILD_INFO.txt hash"
}

$candidate = Get-LabCandidateInfo -PackagePath $CandidatePackage `
    -ExpectedCommit $Commit
$output = (Resolve-Path -LiteralPath $OutputRoot).Path
if (-not (Test-Path -LiteralPath $output -PathType Container)) {
    throw "OutputRoot is not a directory: $output"
}

$sessionPath = Resolve-LabContainedFile -Root $output `
    -RelativePath 'evidence\session.json'
$summaryPath = Resolve-LabContainedFile -Root $output `
    -RelativePath 'evidence\live-summary.json'
$samplesPath = Resolve-LabContainedFile -Root $output `
    -RelativePath 'evidence\live-samples.jsonl'
$rawOverlayPath = Resolve-LabContainedFile -Root $output `
    -RelativePath 'evidence\overlay-path.json'
$sourceReadyCapturePath = Resolve-LabContainedFile -Root $output `
    -RelativePath $SourceReadyCaptureRelativePath
$attestationPath = Resolve-LabContainedFile -Root $output `
    -RelativePath 'evidence\operator-attestation.json'

if (-not $OutFile) {
    $OutFile = Join-Path $output 'evidence\V91-I06-PASS.json'
}
if (-not $LedgerOutFile) {
    $LedgerOutFile = Join-Path $output `
        'evidence\V91-I06-LEDGER-RESULT.json'
}
$resultPath = Get-LabFullPath -Path $OutFile
$ledgerResultPath = Get-LabFullPath -Path $LedgerOutFile
$outputPrefix = $output.TrimEnd([char[]]@('\', '/')) +
    [IO.Path]::DirectorySeparatorChar
foreach ($candidateOutput in @($resultPath, $ledgerResultPath)) {
    if (-not $candidateOutput.StartsWith(
            $outputPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Finalizer output must remain inside OutputRoot: $candidateOutput"
    }
}
$inputPaths = @(
    $sessionPath,
    $summaryPath,
    $samplesPath,
    $rawOverlayPath,
    $sourceReadyCapturePath,
    $attestationPath
)
if ($resultPath -in $inputPaths -or $ledgerResultPath -in $inputPaths) {
    throw 'Output files cannot replace an input evidence file.'
}
if ($resultPath -eq $ledgerResultPath) {
    throw 'OutFile and LedgerOutFile must be different files.'
}
if ((Test-Path -LiteralPath $resultPath) -and -not $Force) {
    throw "Formal result already exists; use -Force to revalidate and replace it: $resultPath"
}
if ((Test-Path -LiteralPath $ledgerResultPath) -and -not $Force) {
    throw (
        'Private ledger result already exists; use -Force to revalidate and ' +
        "replace it: $ledgerResultPath"
    )
}

$session = Get-Content -LiteralPath $sessionPath -Raw | ConvertFrom-Json
Assert-I06Equal `
    -Actual (Get-I06RequiredProperty $session 'schema' 'Viewer session') `
    -Expected 'ese.v91.i06-isolated-viewer/v1' `
    -Context 'Viewer session schema'
Assert-I06Equal `
    -Actual (Get-I06RequiredProperty $session 'case_id' 'Viewer session') `
    -Expected 'V91-I06' -Context 'Viewer session case ID'
Assert-I06CandidateIdentity -Object $session -Candidate $candidate `
    -Context 'Viewer session'
Assert-I06Equal `
    -Actual ([string](Get-I06RequiredProperty $session `
        'candidate_version' 'Viewer session')) `
    -Expected $candidate.version -Context 'Viewer session candidate version'

$sessionDirty = Get-I06RequiredProperty $session 'candidate_dirty' `
    'Viewer session'
if ($sessionDirty -is [bool]) {
    Assert-I06Boolean -Value $sessionDirty -Expected $false `
        -Context 'Viewer session candidate_dirty'
} elseif ([string]$sessionDirty -ne 'false') {
    throw 'Viewer session candidate_dirty must be false.'
}
Assert-I06Boolean `
    -Value (Get-I06RequiredProperty $session 'viewing' 'Viewer session') `
    -Expected $true -Context 'Viewer session viewing'
Assert-I06Equal `
    -Actual ([int](Get-I06RequiredProperty $session `
        'ipv6_mode' 'Viewer session')) `
    -Expected 2 -Context 'Viewer session IPv6 mode'
if ([int](Get-I06RequiredProperty $session `
        'established_route_count' 'Viewer session') -lt 1) {
    throw 'Viewer session contains no established route.'
}

$sessionRemote = Get-I06RequiredProperty $session 'remote' 'Viewer session'
Assert-I06Equal `
    -Actual (Get-I06RequiredProperty $sessionRemote `
        'family' 'Viewer session remote') `
    -Expected 'IPv6' -Context 'Viewer session remote family'
$remoteClass = [string](Get-I06RequiredProperty $sessionRemote `
    'address_class' 'Viewer session remote')
if ($remoteClass -notin @('ula-v6', 'global-v6')) {
    throw "Viewer session remote address class is not usable IPv6: $remoteClass"
}
$remoteAddressHash = [string](Get-I06RequiredProperty $sessionRemote `
    'address_sha256' 'Viewer session remote')
if ($remoteAddressHash -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'Viewer session remote address hash is malformed.'
}
$remoteAddressHash = $remoteAddressHash.ToLowerInvariant()
$remotePort = [int](Get-I06RequiredProperty $sessionRemote `
    'port' 'Viewer session remote')
if ($remotePort -lt 1 -or $remotePort -gt 65535) {
    throw "Viewer session remote port is invalid: $remotePort"
}
$initialChunks = [Int64](Get-I06RequiredProperty $session `
    'initial_chunks_received' 'Viewer session')
if ($initialChunks -lt 1) {
    throw 'Viewer session did not record an initial playable chunk.'
}
$sessionStarted = ConvertTo-I06DateTimeOffset `
    -Value (Get-I06RequiredProperty $session `
        'started_at_utc' 'Viewer session') `
    -Context 'Viewer session start time'
$startupEvidenceAt = ConvertTo-I06DateTimeOffset `
    -Value (Get-I06RequiredProperty $session `
        'startup_evidence_at_utc' 'Viewer session') `
    -Context 'Viewer startup evidence time'
if ($startupEvidenceAt -lt $sessionStarted) {
    throw 'Viewer startup evidence predates the viewer session.'
}

$sessionEvidence = Get-I06RequiredProperty $session 'evidence' `
    'Viewer session'
$routeRelativePath = [string](Get-I06RequiredProperty $sessionEvidence `
    'route' 'Viewer session evidence')
$routePath = Resolve-LabContainedFile -Root $output `
    -RelativePath $routeRelativePath
$route = Get-Content -LiteralPath $routePath -Raw | ConvertFrom-Json
Assert-I06Equal `
    -Actual (Get-I06RequiredProperty $route 'schema' 'Route evidence') `
    -Expected 'ese.v91.i06-isolated-route-start/v1' `
    -Context 'Route evidence schema'
Assert-I06Equal `
    -Actual ([int](Get-I06RequiredProperty $route `
        'process_id' 'Route evidence')) `
    -Expected ([int](Get-I06RequiredProperty $session `
        'process_id' 'Viewer session')) `
    -Context 'Route evidence process ID'
$routeCaptured = ConvertTo-I06DateTimeOffset `
    -Value (Get-I06RequiredProperty $route `
        'captured_at_utc' 'Route evidence') `
    -Context 'Route evidence capture time'
if ($routeCaptured -lt $sessionStarted) {
    throw 'Route evidence predates the viewer session.'
}
$routeExpected = Get-I06RequiredProperty $route 'expected' 'Route evidence'
Assert-I06Equal `
    -Actual (Get-I06RequiredProperty $routeExpected `
        'family' 'Route evidence expected endpoint') `
    -Expected 'IPv6' -Context 'Route evidence family'
Assert-I06Equal `
    -Actual ([string](Get-I06RequiredProperty $routeExpected `
        'remote_address_sha256' 'Route evidence expected endpoint')).ToLowerInvariant() `
    -Expected $remoteAddressHash -Context 'Route evidence remote address hash'
Assert-I06Equal `
    -Actual ([int](Get-I06RequiredProperty $routeExpected `
        'remote_port' 'Route evidence expected endpoint')) `
    -Expected $remotePort -Context 'Route evidence remote port'

$connections = @(Get-I06RequiredProperty $route `
    'matching_connections' 'Route evidence')
if ($connections.Count -lt 1) {
    throw 'Route evidence contains no matching established connection.'
}
$overlayConnections = @($connections | Where-Object {
    [string](Get-I06RequiredProperty $_ 'state' 'Route connection') -eq
        'ESTABLISHED' -and
    [string](Get-I06RequiredProperty $_ 'family' 'Route connection') -eq
        'IPv6' -and
    [string](Get-I06RequiredProperty $_ `
        'interface_class' 'Route connection') -eq 'tailscale-overlay' -and
    [string](Get-I06RequiredProperty $_ `
        'remote_address_sha256' 'Route connection') -eq
        $remoteAddressHash -and
    [int](Get-I06RequiredProperty $_ `
        'remote_port' 'Route connection') -eq $remotePort
})
if ($overlayConnections.Count -lt 1) {
    throw (
        'Route evidence has no established IPv6 connection attributed ' +
        'to the Tailscale overlay and expected remote endpoint.'
    )
}

$attestationJson = Get-Content -LiteralPath $attestationPath -Raw
if ((Protect-LabText -Value $attestationJson -RedactAddresses) -ne
    $attestationJson) {
    throw 'Sanitized operator attestation contains a raw network address.'
}
if ($attestationJson -match
    '(?i)(?:[A-Z]:\\|\\\\[A-Za-z0-9._-]+\\|/Users/|/home/)') {
    throw 'Sanitized operator attestation contains a filesystem path.'
}
$attestation = $attestationJson | ConvertFrom-Json
Assert-I06ExactProperties -Object $attestation -Allowed @(
    'schema',
    'case_id',
    'attested_at_utc',
    'attestor',
    'candidate',
    'topology',
    'operator_observations',
    'observation_times',
    'endpoint_bindings',
    'private_evidence_bindings',
    'limitations',
    'privacy'
) -Context 'Operator attestation'
Assert-I06Equal `
    -Actual (Get-I06RequiredProperty $attestation `
        'schema' 'Operator attestation') `
    -Expected 'ese.v91.i06-sanitized-operator-attestation/v1' `
    -Context 'Operator attestation schema'
Assert-I06Equal `
    -Actual (Get-I06RequiredProperty $attestation `
        'case_id' 'Operator attestation') `
    -Expected 'V91-I06' -Context 'Operator attestation case ID'
$attestedAt = ConvertTo-I06DateTimeOffset `
    -Value (Get-I06RequiredProperty $attestation `
        'attested_at_utc' 'Operator attestation') `
    -Context 'Operator attestation time'

$attestor = Get-I06RequiredProperty $attestation `
    'attestor' 'Operator attestation'
Assert-I06ExactProperties -Object $attestor -Allowed @(
    'kind',
    'identity_disclosed',
    'cryptographically_signed',
    'assurance'
) -Context 'Operator attestor'
Assert-I06Equal `
    -Actual (Get-I06RequiredProperty $attestor `
        'kind' 'Operator attestor') `
    -Expected 'human_operator' -Context 'Operator attestor kind'
Assert-I06Boolean `
    -Value (Get-I06RequiredProperty $attestor `
        'identity_disclosed' 'Operator attestor') `
    -Expected $false -Context 'Operator attestor identity disclosure'
Assert-I06Boolean `
    -Value (Get-I06RequiredProperty $attestor `
        'cryptographically_signed' 'Operator attestor') `
    -Expected $false -Context 'Operator attestation signature status'
Assert-I06Equal `
    -Actual (Get-I06RequiredProperty $attestor `
        'assurance' 'Operator attestor') `
    -Expected 'explicit-operator-confirmation' `
    -Context 'Operator attestation assurance'

$attestedCandidate = Get-I06RequiredProperty $attestation `
    'candidate' 'Operator attestation'
Assert-I06ExactProperties -Object $attestedCandidate -Allowed @(
    'version',
    'commit',
    'emule_sha256',
    'ese_server_sha256',
    'build_info_sha256'
) -Context 'Operator-attested candidate'
Assert-I06CandidateIdentity -Object $attestedCandidate `
    -Candidate $candidate -Context 'Operator-attested candidate' `
    -CommitProperty 'commit' -BinaryProperty 'emule_sha256' `
    -ServerProperty 'ese_server_sha256' `
    -BuildInfoProperty 'build_info_sha256'
Assert-I06Equal `
    -Actual ([string](Get-I06RequiredProperty $attestedCandidate `
        'version' 'Operator-attested candidate')) `
    -Expected $candidate.version `
    -Context 'Operator-attested candidate version'

$attestedTopology = Get-I06RequiredProperty $attestation `
    'topology' 'Operator attestation'
Assert-I06ExactProperties -Object $attestedTopology -Allowed @(
    'id',
    'physical_windows_count',
    'separate_physical_machines',
    'roles',
    'transport',
    'address_family',
    'address_scope',
    'observed_path',
    'native_public_ipv6'
) -Context 'Operator-attested topology'
Assert-I06Equal `
    -Actual (Get-I06RequiredProperty $attestedTopology `
        'id' 'Operator-attested topology') `
    -Expected 'T6' -Context 'Operator-attested topology ID'
Assert-I06Equal `
    -Actual ([int](Get-I06RequiredProperty $attestedTopology `
        'physical_windows_count' 'Operator-attested topology')) `
    -Expected 2 -Context 'Operator-attested physical Windows count'
Assert-I06Boolean `
    -Value (Get-I06RequiredProperty $attestedTopology `
        'separate_physical_machines' 'Operator-attested topology') `
    -Expected $true `
    -Context 'Operator-attested physical machine separation'
Assert-I06Equal `
    -Actual (Get-I06RequiredProperty $attestedTopology `
        'transport' 'Operator-attested topology') `
    -Expected 'Tailscale overlay' `
    -Context 'Operator-attested overlay transport'
Assert-I06Equal `
    -Actual (Get-I06RequiredProperty $attestedTopology `
        'address_family' 'Operator-attested topology') `
    -Expected 'IPv6' -Context 'Operator-attested address family'
Assert-I06Equal `
    -Actual (Get-I06RequiredProperty $attestedTopology `
        'address_scope' 'Operator-attested topology') `
    -Expected 'ULA' -Context 'Operator-attested address scope'
Assert-I06Boolean `
    -Value (Get-I06RequiredProperty $attestedTopology `
        'native_public_ipv6' 'Operator-attested topology') `
    -Expected $false -Context 'Operator-attested native public IPv6'

$attestedRoles = @(Get-I06RequiredProperty $attestedTopology `
    'roles' 'Operator-attested topology')
if ($attestedRoles.Count -ne 2) {
    throw 'Operator attestation must contain exactly two pseudonymous roles.'
}
$expectedRoles = [ordered]@{
    'viewer-node' = 'LiveTV viewer'
    'source-node' = 'LiveTV source'
}
$observedRoleIds = @()
foreach ($role in $attestedRoles) {
    Assert-I06ExactProperties -Object $role -Allowed @(
        'role_id',
        'function',
        'os_family',
        'physical_machine'
    ) -Context 'Operator-attested role'
    $roleId = [string](Get-I06RequiredProperty $role `
        'role_id' 'Operator-attested role')
    if (-not $expectedRoles.Contains($roleId)) {
        throw "Operator attestation contains unexpected role '$roleId'."
    }
    if ($roleId -in $observedRoleIds) {
        throw "Operator attestation repeats role '$roleId'."
    }
    $observedRoleIds += $roleId
    Assert-I06Equal `
        -Actual (Get-I06RequiredProperty $role `
            'function' "Operator-attested role $roleId") `
        -Expected $expectedRoles[$roleId] `
        -Context "Operator-attested role $roleId function"
    Assert-I06Equal `
        -Actual (Get-I06RequiredProperty $role `
            'os_family' "Operator-attested role $roleId") `
        -Expected 'Windows' `
        -Context "Operator-attested role $roleId OS"
    Assert-I06Boolean `
        -Value (Get-I06RequiredProperty $role `
            'physical_machine' "Operator-attested role $roleId") `
        -Expected $true `
        -Context "Operator-attested role $roleId physical status"
}

$operatorObservations = Get-I06RequiredProperty $attestation `
    'operator_observations' 'Operator attestation'
$expectedObservationNames = @(
    'viewer_execution_observed',
    'source_interactive_rdp_observed',
    'source_ready_observed',
    'source_candidate_identity_observed_in_ready',
    'source_and_viewer_confirmed_separate'
)
Assert-I06ExactProperties -Object $operatorObservations `
    -Allowed $expectedObservationNames -Context 'Operator observations'
foreach ($observationName in @(
    $expectedObservationNames
)) {
    Assert-I06Boolean `
        -Value (Get-I06RequiredProperty $operatorObservations `
            $observationName 'Operator observations') `
        -Expected $true -Context "Operator observation $observationName"
}

$observationTimes = Get-I06RequiredProperty $attestation `
    'observation_times' 'Operator attestation'
Assert-I06ExactProperties -Object $observationTimes -Allowed @(
    'viewer_session_started_at_utc',
    'startup_route_captured_at_utc',
    'overlay_path_observed_at_utc'
) -Context 'Operator observation times'
$attestedSessionStarted = ConvertTo-I06DateTimeOffset `
    -Value (Get-I06RequiredProperty $observationTimes `
        'viewer_session_started_at_utc' 'Operator observation times') `
    -Context 'Attested viewer session start'
$attestedRouteCaptured = ConvertTo-I06DateTimeOffset `
    -Value (Get-I06RequiredProperty $observationTimes `
        'startup_route_captured_at_utc' 'Operator observation times') `
    -Context 'Attested startup route capture'
$attestedOverlayCaptured = ConvertTo-I06DateTimeOffset `
    -Value (Get-I06RequiredProperty $observationTimes `
        'overlay_path_observed_at_utc' 'Operator observation times') `
    -Context 'Attested overlay path observation'
Assert-I06Equal -Actual $attestedSessionStarted `
    -Expected $sessionStarted `
    -Context 'Attested versus actual viewer session start'
Assert-I06Equal -Actual $attestedRouteCaptured `
    -Expected $routeCaptured `
    -Context 'Attested versus actual route capture time'
if ($attestedOverlayCaptured -lt $sessionStarted) {
    throw 'Attested overlay path observation predates the viewer session.'
}
if ($attestedAt -lt $attestedOverlayCaptured) {
    throw 'Operator attestation predates its overlay path observation.'
}

$attestedPath = Get-I06RequiredProperty $attestedTopology `
    'observed_path' 'Operator-attested topology'
Assert-I06ExactProperties -Object $attestedPath -Allowed @(
    'kind',
    'region',
    'direct'
) -Context 'Operator-attested path'
Assert-I06Equal `
    -Actual (Get-I06RequiredProperty $attestedPath `
        'kind' 'Operator-attested path') `
    -Expected 'DERP' -Context 'Operator-attested path kind'
$derpRegion = [string](Get-I06RequiredProperty $attestedPath `
    'region' 'Operator-attested path')
if ([string]::IsNullOrWhiteSpace($derpRegion) -or
    $derpRegion -notmatch '^[A-Za-z0-9_-]{1,32}$') {
    throw 'Operator-attested DERP region is missing or malformed.'
}
Assert-I06Boolean `
    -Value (Get-I06RequiredProperty $attestedPath `
        'direct' 'Operator-attested path') `
    -Expected $false -Context 'Operator-attested path direct'

$endpointBindings = Get-I06RequiredProperty $attestation `
    'endpoint_bindings' 'Operator attestation'
Assert-I06ExactProperties -Object $endpointBindings -Allowed @(
    'viewer_address_sha256',
    'source_address_sha256',
    'raw_addresses_embedded'
) -Context 'Operator endpoint bindings'
$viewerAddressHash = [string](Get-I06RequiredProperty $endpointBindings `
    'viewer_address_sha256' 'Operator endpoint bindings')
$sourceAddressHash = [string](Get-I06RequiredProperty $endpointBindings `
    'source_address_sha256' 'Operator endpoint bindings')
foreach ($binding in @(
    [pscustomobject]@{ name = 'viewer'; value = $viewerAddressHash },
    [pscustomobject]@{ name = 'source'; value = $sourceAddressHash }
)) {
    if ($binding.value -notmatch '^[0-9A-Fa-f]{64}$') {
        throw "Operator $($binding.name) endpoint hash is malformed."
    }
}
$viewerAddressHash = $viewerAddressHash.ToLowerInvariant()
$sourceAddressHash = $sourceAddressHash.ToLowerInvariant()
Assert-I06Boolean `
    -Value (Get-I06RequiredProperty $endpointBindings `
        'raw_addresses_embedded' 'Operator endpoint bindings') `
    -Expected $false -Context 'Operator raw-address embedding'
Assert-I06Equal -Actual $sourceAddressHash `
    -Expected $remoteAddressHash `
    -Context 'Attested source versus viewer-session remote endpoint'
if (@($overlayConnections | Where-Object {
        [string](Get-I06RequiredProperty $_ `
            'local_address_sha256' 'Route connection') -eq
            $viewerAddressHash
    }).Count -lt 1) {
    throw (
        'No Tailscale route connection matches the attested viewer ' +
        'endpoint hash.'
    )
}

$expectedPrivateBindings = [ordered]@{
    viewer_session = [pscustomobject]@{
        schema = 'ese.v91.i06-isolated-viewer/v1'
        sha256 = Get-LabSha256 -Path $sessionPath
    }
    startup_route = [pscustomobject]@{
        schema = 'ese.v91.i06-isolated-route-start/v1'
        sha256 = Get-LabSha256 -Path $routePath
    }
    raw_overlay_observation = [pscustomobject]@{
        schema = 'ese.v91.i06-overlay-path/v1'
        sha256 = Get-LabSha256 -Path $rawOverlayPath
    }
    source_ready_private_capture = [pscustomobject]@{
        media_type = 'image/jpeg'
        sha256 = Get-LabSha256 -Path $sourceReadyCapturePath
    }
}
$privateBindings = @(Get-I06RequiredProperty $attestation `
    'private_evidence_bindings' 'Operator attestation')
if ($privateBindings.Count -ne $expectedPrivateBindings.Count) {
    throw 'Operator attestation has an unexpected private-binding count.'
}
$observedBindingRoles = @()
foreach ($binding in $privateBindings) {
    $bindingRole = [string](Get-I06RequiredProperty $binding `
        'role' 'Operator private evidence binding')
    if (-not $expectedPrivateBindings.Contains($bindingRole)) {
        throw "Operator attestation contains unexpected binding '$bindingRole'."
    }
    if ($bindingRole -in $observedBindingRoles) {
        throw "Operator attestation repeats binding '$bindingRole'."
    }
    $observedBindingRoles += $bindingRole
    $expectedBinding = $expectedPrivateBindings[$bindingRole]
    $allowedBindingProperties = if (
        $null -ne $expectedBinding.PSObject.Properties['schema']
    ) {
        @('role', 'schema', 'sha256')
    } else {
        @('role', 'media_type', 'sha256')
    }
    Assert-I06ExactProperties -Object $binding `
        -Allowed $allowedBindingProperties `
        -Context "Operator binding $bindingRole"
    Assert-I06Equal `
        -Actual ([string](Get-I06RequiredProperty $binding `
            'sha256' "Operator binding $bindingRole")).ToLowerInvariant() `
        -Expected $expectedBinding.sha256 `
        -Context "Operator binding $bindingRole hash"
    if ($null -ne $expectedBinding.PSObject.Properties['schema']) {
        Assert-I06Equal `
            -Actual (Get-I06RequiredProperty $binding `
                'schema' "Operator binding $bindingRole") `
            -Expected $expectedBinding.schema `
            -Context "Operator binding $bindingRole schema"
    }
    if ($null -ne $expectedBinding.PSObject.Properties['media_type']) {
        Assert-I06Equal `
            -Actual (Get-I06RequiredProperty $binding `
                'media_type' "Operator binding $bindingRole") `
            -Expected $expectedBinding.media_type `
            -Context "Operator binding $bindingRole media type"
    }
}

$attestationPrivacy = Get-I06RequiredProperty $attestation `
    'privacy' 'Operator attestation'
Assert-I06ExactProperties -Object $attestationPrivacy -Allowed @(
    'public_safe',
    'hostnames_embedded',
    'network_addresses_embedded',
    'stream_keys_embedded',
    'process_ids_embedded',
    'filesystem_paths_embedded',
    'private_evidence_contents_embedded'
) -Context 'Operator attestation privacy'
Assert-I06Boolean `
    -Value (Get-I06RequiredProperty $attestationPrivacy `
        'public_safe' 'Operator attestation privacy') `
    -Expected $true -Context 'Operator attestation public-safe status'
foreach ($privacyName in @(
    'hostnames_embedded',
    'network_addresses_embedded',
    'stream_keys_embedded',
    'process_ids_embedded',
    'filesystem_paths_embedded',
    'private_evidence_contents_embedded'
)) {
    Assert-I06Boolean `
        -Value (Get-I06RequiredProperty $attestationPrivacy `
            $privacyName 'Operator attestation privacy') `
        -Expected $false -Context "Operator privacy $privacyName"
}

$summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
Assert-I06Equal `
    -Actual (Get-I06RequiredProperty $summary 'schema' 'Soak summary') `
    -Expected 'ese.lab.live-ipv6-soak-summary/v1' `
    -Context 'Soak summary schema'
Assert-I06Equal `
    -Actual (Get-I06RequiredProperty $summary 'verdict' 'Soak summary') `
    -Expected 'PASS' -Context 'Soak summary verdict'
if (@(Get-I06RequiredProperty $summary `
        'failures' 'Soak summary').Count -ne 0) {
    throw 'Soak summary contains one or more failures.'
}
$requestedDuration = [int](Get-I06RequiredProperty $summary `
    'requested_duration_seconds' 'Soak summary')
if ($requestedDuration -lt 300) {
    throw "Soak requested only $requestedDuration seconds; at least 300 are required."
}
$summaryStarted = ConvertTo-I06DateTimeOffset `
    -Value (Get-I06RequiredProperty $summary `
        'started_at_utc' 'Soak summary') `
    -Context 'Soak start time'
$summaryFinished = ConvertTo-I06DateTimeOffset `
    -Value (Get-I06RequiredProperty $summary `
        'finished_at_utc' 'Soak summary') `
    -Context 'Soak finish time'
$actualDuration = ($summaryFinished - $summaryStarted).TotalSeconds
if ($actualDuration -lt 300) {
    throw (
        'Soak wall-clock duration is shorter than 300 seconds: ' +
        "$([Math]::Round($actualDuration, 3))."
    )
}
if ($actualDuration + 1 -lt $requestedDuration) {
    throw (
        'Soak wall-clock duration is shorter than its requested duration: ' +
        "$([Math]::Round($actualDuration, 3)) of $requestedDuration seconds."
    )
}
if ($summaryStarted -lt $sessionStarted -or
    $summaryStarted -lt $startupEvidenceAt) {
    throw 'Soak summary predates the validated viewer startup evidence.'
}
if ($routeCaptured -gt $summaryFinished.AddSeconds(5)) {
    throw 'Route evidence was captured after the soak ended.'
}
if ($attestedOverlayCaptured -lt $summaryStarted.AddSeconds(-5) -or
    $attestedOverlayCaptured -gt $summaryFinished.AddSeconds(5)) {
    throw 'Overlay path observation falls outside the soak interval.'
}
Assert-I06Equal `
    -Actual ([string](Get-I06RequiredProperty $summary `
        'samples_file' 'Soak summary')) `
    -Expected ([IO.Path]::GetFileName($samplesPath)) `
    -Context 'Soak summary samples filename'

$sampleCount = 0
$firstChunks = $null
$lastChunks = $null
$previousChunks = $null
$previousCaptured = $null
$firstCaptured = $null
$lastCaptured = $null
foreach ($line in [IO.File]::ReadLines($samplesPath)) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $sampleCount++
    try {
        $sample = $line | ConvertFrom-Json
    } catch {
        throw "Sample line $sampleCount is not valid JSON: $($_.Exception.Message)"
    }
    $context = "Sample $sampleCount"
    Assert-I06Equal `
        -Actual (Get-I06RequiredProperty $sample 'schema' $context) `
        -Expected 'ese.lab.live-ipv6-soak-sample/v1' `
        -Context "$context schema"
    Assert-I06Equal `
        -Actual ([int](Get-I06RequiredProperty $sample `
            'sample_number' $context)) `
        -Expected $sampleCount -Context "$context sequence number"
    Assert-I06Boolean `
        -Value (Get-I06RequiredProperty $sample 'viewing' $context) `
        -Expected $true -Context "$context viewing"
    Assert-I06Boolean `
        -Value (Get-I06RequiredProperty $sample `
            'playlist_valid' $context) `
        -Expected $true -Context "$context playlist"
    if ([int](Get-I06RequiredProperty $sample `
            'ipv6_connection_count' $context) -lt 1) {
        throw "$context contains no established IPv6 data connection."
    }
    if ([int](Get-I06RequiredProperty $sample `
            'ipv4_fallback_count' $context) -ne 0) {
        throw "$context detected an IPv4 fallback."
    }
    if (@(Get-I06RequiredProperty $sample `
            'failures' $context).Count -ne 0) {
        throw "$context contains one or more monitor failures."
    }

    $chunks = Get-I06RequiredProperty $sample 'chunks' $context
    if ([int](Get-I06RequiredProperty $chunks `
            'missing' "$context chunks") -ne 0) {
        throw "$context contains missing playlist chunks."
    }
    $counters = Get-I06RequiredProperty $sample 'counters' $context
    $received = [Int64](Get-I06RequiredProperty $counters `
        'chunksReceived' "$context counters")
    if ($received -lt 0) {
        throw "$context contains a negative received-chunk counter."
    }
    if ($null -ne $previousChunks -and $received -lt $previousChunks) {
        throw "$context received-chunk counter moved backwards."
    }

    $captured = ConvertTo-I06DateTimeOffset `
        -Value (Get-I06RequiredProperty $sample `
            'captured_at_utc' $context) `
        -Context "$context capture time"
    if ($null -ne $previousCaptured -and $captured -lt $previousCaptured) {
        throw "$context capture time moved backwards."
    }
    if ($captured -lt $summaryStarted.AddSeconds(-5) -or
        $captured -gt $summaryFinished.AddSeconds(5)) {
        throw "$context capture time falls outside the soak interval."
    }

    if ($null -eq $firstChunks) {
        $firstChunks = $received
        $firstCaptured = $captured
    }
    $lastChunks = $received
    $lastCaptured = $captured
    $previousChunks = $received
    $previousCaptured = $captured
}
if ($sampleCount -lt 2) {
    throw 'At least two valid soak samples are required.'
}
$sampleCoverage = ($lastCaptured - $firstCaptured).TotalSeconds
$intervalSeconds = [int](Get-I06RequiredProperty $summary `
    'interval_seconds' 'Soak summary')
if ($intervalSeconds -lt 2 -or $intervalSeconds -gt 300) {
    throw "Soak summary interval is invalid: $intervalSeconds seconds."
}
$minimumSampleCoverage = [Math]::Max(
    0.0, 300.0 - [double]$intervalSeconds - 5.0)
if ($sampleCoverage -lt $minimumSampleCoverage) {
    throw (
        'Soak samples do not span the required test window: ' +
        "$([Math]::Round($sampleCoverage, 3)) seconds observed; " +
        "$([Math]::Round($minimumSampleCoverage, 3)) required."
    )
}
Assert-I06Equal -Actual $sampleCount `
    -Expected ([int](Get-I06RequiredProperty $summary `
        'sample_count' 'Soak summary')) `
    -Context 'Soak sample count'
Assert-I06Equal -Actual $firstChunks `
    -Expected ([Int64](Get-I06RequiredProperty $summary `
        'first_chunks_received' 'Soak summary')) `
    -Context 'First received-chunk counter'
Assert-I06Equal -Actual $lastChunks `
    -Expected ([Int64](Get-I06RequiredProperty $summary `
        'last_chunks_received' 'Soak summary')) `
    -Context 'Last received-chunk counter'
if ($lastChunks -le $firstChunks -or $lastChunks -le $initialChunks) {
    throw 'Received-chunk counter did not advance during the soak.'
}

$privateEvidenceFiles = @(
    [pscustomobject][ordered]@{
        role = 'viewer_session'
        schema = 'ese.v91.i06-isolated-viewer/v1'
        path = Get-LabRelativePath -BasePath $output -Path $sessionPath
        sha256 = Get-LabSha256 -Path $sessionPath
    },
    [pscustomobject][ordered]@{
        role = 'startup_route'
        schema = 'ese.v91.i06-isolated-route-start/v1'
        path = Get-LabRelativePath -BasePath $output -Path $routePath
        sha256 = Get-LabSha256 -Path $routePath
    },
    [pscustomobject][ordered]@{
        role = 'raw_overlay_observation'
        schema = 'ese.v91.i06-overlay-path/v1'
        path = Get-LabRelativePath -BasePath $output -Path $rawOverlayPath
        sha256 = Get-LabSha256 -Path $rawOverlayPath
    },
    [pscustomobject][ordered]@{
        role = 'source_ready_private_capture'
        media_type = 'image/jpeg'
        path = Get-LabRelativePath -BasePath $output `
            -Path $sourceReadyCapturePath
        sha256 = Get-LabSha256 -Path $sourceReadyCapturePath
    },
    [pscustomobject][ordered]@{
        role = 'sanitized_operator_attestation'
        schema = 'ese.v91.i06-sanitized-operator-attestation/v1'
        path = Get-LabRelativePath -BasePath $output -Path $attestationPath
        sha256 = Get-LabSha256 -Path $attestationPath
    },
    [pscustomobject][ordered]@{
        role = 'soak_summary'
        schema = 'ese.lab.live-ipv6-soak-summary/v1'
        path = Get-LabRelativePath -BasePath $output -Path $summaryPath
        sha256 = Get-LabSha256 -Path $summaryPath
    },
    [pscustomobject][ordered]@{
        role = 'soak_samples'
        schema = 'ese.lab.live-ipv6-soak-sample/v1'
        path = Get-LabRelativePath -BasePath $output -Path $samplesPath
        sha256 = Get-LabSha256 -Path $samplesPath
    }
)
$publicEvidenceBindings = @($privateEvidenceFiles | ForEach-Object {
    $binding = [ordered]@{
        role = $_.role
        sha256 = $_.sha256
        visibility = if ($_.role -eq 'sanitized_operator_attestation') {
            'public-safe'
        } else {
            'private'
        }
    }
    if ($_.PSObject.Properties.Name -contains 'schema') {
        $binding.schema = $_.schema
    }
    if ($_.PSObject.Properties.Name -contains 'media_type') {
        $binding.media_type = $_.media_type
    }
    [pscustomobject]$binding
})

$result = [ordered]@{
    schema = 'ese.v91.i06-overlay-final/v2'
    id = 'V91-I06'
    case_id = 'V91-I06'
    status = 'PASS'
    formal_verdict = 'PASS'
    executed = $true
    execution_state = 'COMPLETE'
    required_topology = 'T6'
    adjudicated_at_utc = Get-LabUtcTimestamp
    reason = (
        'Remote LiveTV transfer remained functional for at least 300 seconds ' +
        'over an IPv6 Tailscale overlay path observed through DERP.'
    )
    claim_scope = (
        'Validated on IPv6 overlay transport only; this does not prove ' +
        'native, direct, or publicly reachable IPv6.'
    )
    candidate_version = $candidate.version
    candidate_commit = $candidate.commit
    candidate_binary_sha256 = $candidate.emule_sha256
    candidate_ese_server_sha256 = $candidate.ese_server_sha256
    candidate_build_info_sha256 = $candidate.build_info_sha256
    topology = [ordered]@{
        id = 'T6'
        physical_windows_count = 2
        separate_physical_machines = $true
        roles = @(
            [pscustomobject][ordered]@{
                role_id = 'viewer-node'
                function = 'LiveTV viewer'
                os_family = 'Windows'
                physical_machine = $true
            },
            [pscustomobject][ordered]@{
                role_id = 'source-node'
                function = 'LiveTV source'
                os_family = 'Windows'
                physical_machine = $true
            }
        )
        transport = 'Tailscale overlay'
        address_family = 'IPv6'
        address_scope = 'ULA'
        path = 'DERP'
        derp_region = $derpRegion
        direct = $false
        native_public_ipv6 = $false
        physical_topology_assurance = 'explicit-operator-confirmation'
    }
    source_observation = [ordered]@{
        interactive_rdp_observed = $true
        ready_state_observed = $true
        candidate_identity_observed_in_ready = $true
    }
    transfer = [ordered]@{
        kind = 'LiveTV'
        requested_duration_seconds = $requestedDuration
        actual_duration_seconds = [Math]::Round($actualDuration, 3)
        sample_count = $sampleCount
        first_sample_at_utc = $firstCaptured.ToString('o')
        last_sample_at_utc = $lastCaptured.ToString('o')
        chunks_received_first = $firstChunks
        chunks_received_last = $lastChunks
        chunks_received_delta = $lastChunks - $firstChunks
        viewing_all_samples = $true
        playlist_valid_all_samples = $true
        ipv6_connection_all_samples = $true
        ipv4_fallback_observed = $false
        missing_playlist_chunks_all_samples = 0
        monitor_failures = 0
    }
    evidence_bindings = $publicEvidenceBindings
    assurance = [ordered]@{
        automated = @(
            'exact candidate identity',
            'established IPv6 Tailscale-overlay socket',
            '300-second LiveTV sample invariants',
            'private evidence SHA-256 bindings'
        )
        operator_attested = @(
            'two separate physical Windows computers',
            'viewer execution observed',
            'interactive RDP session to the source observed',
            'source READY and exact candidate identity observed'
        )
        operator_identity_disclosed = $false
        operator_attestation_cryptographically_signed = $false
    }
    privacy = [ordered]@{
        public_safe = $true
        self_contained_adjudication = $true
        evidence_paths_embedded = $false
        hostnames_embedded = $false
        network_addresses_embedded = $false
        stream_keys_embedded = $false
        process_ids_embedded = $false
        raw_evidence_contents_embedded = $false
    }
    failures = @()
}

$written = Write-LabJson -Value $result -Path $resultPath
$publicResultHash = Get-LabSha256 -Path $resultPath
$publicResultRelative = (
    Get-LabRelativePath -BasePath $output -Path $resultPath
).Replace('\', '/')
$attestationRelative = (
    Get-LabRelativePath -BasePath $output -Path $attestationPath
).Replace('\', '/')
$ledgerEvidencePaths = @($publicResultRelative, $attestationRelative)
$ledgerResult = [ordered]@{
    schema = 'ese.v91.i06-overlay-ledger-result/v1'
    id = 'V91-I06'
    case_id = 'V91-I06'
    status = 'PASS'
    executed = $true
    execution_state = 'COMPLETE'
    required_topology = 'T6'
    reason = $result.reason
    candidate_version = $candidate.version
    candidate_commit = $candidate.commit
    candidate_binary_sha256 = $candidate.emule_sha256
    candidate_ese_server_sha256 = $candidate.ese_server_sha256
    candidate_build_info_sha256 = $candidate.build_info_sha256
    public_result = [ordered]@{
        schema = $result.schema
        sha256 = $publicResultHash
    }
    evidence = $ledgerEvidencePaths
    privacy = [ordered]@{
        classification = 'internal'
        publish = $false
        contains_relative_private_evidence_paths = $false
        raw_evidence_bound_by_public_result_hashes = $true
    }
}
$ledgerWritten = Write-LabJson -Value $ledgerResult `
    -Path $ledgerResultPath
Write-Host "V91-I06 sanitized formal PASS written: $written" `
    -ForegroundColor Green
Write-Host "Private ledger companion written: $ledgerWritten"
$result | ConvertTo-Json -Depth 12
