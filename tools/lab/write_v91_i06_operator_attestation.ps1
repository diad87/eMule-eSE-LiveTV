<#
.SYNOPSIS
Creates a sanitized operator attestation for the V91-I06 physical T6 run.

.DESCRIPTION
Converts private V91-I06 source/viewer observations into a machine-readable
attestation that contains no hostnames, network addresses, stream keys, PIDs,
or filesystem paths. The private inputs remain in the run directory and are
bound only by schema and SHA-256.

The four confirmation switches are intentionally explicit. This helper cannot
discover whether a Windows host is a separate physical computer or whether an
operator saw READY over RDP; it records those facts only when the operator
confirms them.

.PARAMETER SourceReadyCaptureRelativePath
Private READY capture path relative to OutputRoot. Its contents are never
embedded; only its SHA-256 is included in the sanitized attestation.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CandidatePackage,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$Commit,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmTwoSeparatePhysicalWindows,
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmViewerExecutionObserved,
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmSourceRdpObserved,
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmSourceReadyAndCandidateObserved,
    [string]$SourceReadyCaptureRelativePath =
        'evidence\source-ready-private.jpg',
    [string]$OutFile = '',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

function Get-I06AttestationProperty {
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

function Assert-I06AttestationEqual {
    param(
        [AllowNull()]$Actual,
        [AllowNull()]$Expected,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if ($Actual -ne $Expected) {
        throw "$Context mismatch: actual='$Actual' expected='$Expected'."
    }
}

function ConvertTo-I06AttestationIPv6 {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $parsed = $null
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text) -or
        -not [Net.IPAddress]::TryParse(
            $text.Split('%')[0], [ref]$parsed) -or
        $parsed.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetworkV6) {
        throw "$Context is not an IPv6 address."
    }
    return $parsed
}

function ConvertTo-I06AttestationDateTimeOffset {
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

foreach ($confirmation in @(
    [pscustomobject]@{
        name = 'ConfirmTwoSeparatePhysicalWindows'
        value = $ConfirmTwoSeparatePhysicalWindows
    },
    [pscustomobject]@{
        name = 'ConfirmViewerExecutionObserved'
        value = $ConfirmViewerExecutionObserved
    },
    [pscustomobject]@{
        name = 'ConfirmSourceRdpObserved'
        value = $ConfirmSourceRdpObserved
    },
    [pscustomobject]@{
        name = 'ConfirmSourceReadyAndCandidateObserved'
        value = $ConfirmSourceReadyAndCandidateObserved
    }
)) {
    if (-not [bool]$confirmation.value) {
        throw (
            "Operator confirmation -$($confirmation.name) is required. " +
            'Do not provide it unless the fact was directly observed.'
        )
    }
}

$candidate = Get-LabCandidateInfo -PackagePath $CandidatePackage `
    -ExpectedCommit $Commit
$output = (Resolve-Path -LiteralPath $OutputRoot).Path
if (-not (Test-Path -LiteralPath $output -PathType Container)) {
    throw "OutputRoot is not a directory: $output"
}

$sessionPath = Resolve-LabContainedFile -Root $output `
    -RelativePath 'evidence\session.json'
$routePath = Resolve-LabContainedFile -Root $output `
    -RelativePath 'evidence\route-start.json'
$rawOverlayPath = Resolve-LabContainedFile -Root $output `
    -RelativePath 'evidence\overlay-path.json'
$sourceReadyCapturePath = Resolve-LabContainedFile -Root $output `
    -RelativePath $SourceReadyCaptureRelativePath
if (-not $OutFile) {
    $OutFile = Join-Path $output 'evidence\operator-attestation.json'
}
$attestationPath = Get-LabFullPath -Path $OutFile
if ($attestationPath -in @(
        $sessionPath,
        $routePath,
        $rawOverlayPath,
        $sourceReadyCapturePath
    )) {
    throw 'OutFile cannot replace a private input evidence file.'
}
if ((Test-Path -LiteralPath $attestationPath) -and -not $Force) {
    throw (
        'Operator attestation already exists; use -Force to revalidate and ' +
        "replace it: $attestationPath"
    )
}

$session = Get-Content -LiteralPath $sessionPath -Raw | ConvertFrom-Json
Assert-I06AttestationEqual `
    -Actual (Get-I06AttestationProperty $session 'schema' 'Viewer session') `
    -Expected 'ese.v91.i06-isolated-viewer/v1' `
    -Context 'Viewer session schema'
Assert-I06AttestationEqual `
    -Actual (Get-I06AttestationProperty $session 'case_id' 'Viewer session') `
    -Expected 'V91-I06' -Context 'Viewer session case ID'
foreach ($identity in @(
    [pscustomobject]@{
        name = 'commit'
        actual = [string](Get-I06AttestationProperty $session `
            'candidate_commit' 'Viewer session')
        expected = $candidate.commit
    },
    [pscustomobject]@{
        name = 'emule.exe hash'
        actual = [string](Get-I06AttestationProperty $session `
            'candidate_binary_sha256' 'Viewer session')
        expected = $candidate.emule_sha256
    },
    [pscustomobject]@{
        name = 'ese-server.exe hash'
        actual = [string](Get-I06AttestationProperty $session `
            'candidate_ese_server_sha256' 'Viewer session')
        expected = $candidate.ese_server_sha256
    },
    [pscustomobject]@{
        name = 'BUILD_INFO.txt hash'
        actual = [string](Get-I06AttestationProperty $session `
            'candidate_build_info_sha256' 'Viewer session')
        expected = $candidate.build_info_sha256
    }
)) {
    Assert-I06AttestationEqual `
        -Actual $identity.actual.ToLowerInvariant() `
        -Expected $identity.expected `
        -Context "Viewer session $($identity.name)"
}

$sessionRemote = Get-I06AttestationProperty $session `
    'remote' 'Viewer session'
Assert-I06AttestationEqual `
    -Actual (Get-I06AttestationProperty $sessionRemote `
        'family' 'Viewer session remote') `
    -Expected 'IPv6' -Context 'Viewer session remote family'
$sourceAddressHash = [string](Get-I06AttestationProperty $sessionRemote `
    'address_sha256' 'Viewer session remote')
if ($sourceAddressHash -notmatch '^[0-9A-Fa-f]{64}$') {
    throw 'Viewer session remote address hash is malformed.'
}
$sourceAddressHash = $sourceAddressHash.ToLowerInvariant()
$sourcePort = [int](Get-I06AttestationProperty $sessionRemote `
    'port' 'Viewer session remote')
$viewerSessionStarted = ConvertTo-I06AttestationDateTimeOffset `
    -Value (Get-I06AttestationProperty $session `
        'started_at_utc' 'Viewer session') `
    -Context 'Viewer session start time'

$route = Get-Content -LiteralPath $routePath -Raw | ConvertFrom-Json
Assert-I06AttestationEqual `
    -Actual (Get-I06AttestationProperty $route 'schema' 'Route evidence') `
    -Expected 'ese.v91.i06-isolated-route-start/v1' `
    -Context 'Route evidence schema'
$startupRouteCaptured = ConvertTo-I06AttestationDateTimeOffset `
    -Value (Get-I06AttestationProperty $route `
        'captured_at_utc' 'Route evidence') `
    -Context 'Route evidence capture time'
if ($startupRouteCaptured -lt $viewerSessionStarted) {
    throw 'Route evidence predates the viewer session.'
}
$routeConnections = @(Get-I06AttestationProperty $route `
    'matching_connections' 'Route evidence')
$matchingRoutes = @($routeConnections | Where-Object {
    [string](Get-I06AttestationProperty $_ `
        'state' 'Route connection') -eq 'ESTABLISHED' -and
    [string](Get-I06AttestationProperty $_ `
        'family' 'Route connection') -eq 'IPv6' -and
    [string](Get-I06AttestationProperty $_ `
        'interface_class' 'Route connection') -eq 'tailscale-overlay' -and
    [string](Get-I06AttestationProperty $_ `
        'remote_address_sha256' 'Route connection') -eq
        $sourceAddressHash -and
    [int](Get-I06AttestationProperty $_ `
        'remote_port' 'Route connection') -eq $sourcePort
})
if ($matchingRoutes.Count -lt 1) {
    throw (
        'Route evidence does not bind the viewer to the expected source ' +
        'through an established IPv6 Tailscale-overlay socket.'
    )
}
$viewerAddressHashes = @($matchingRoutes | ForEach-Object {
    [string](Get-I06AttestationProperty $_ `
        'local_address_sha256' 'Route connection')
} | Sort-Object -Unique)
if ($viewerAddressHashes.Count -ne 1 -or
    $viewerAddressHashes[0] -notmatch '^[0-9A-Fa-f]{64}$') {
    throw 'Route evidence does not provide one unambiguous viewer-address hash.'
}
$viewerAddressHash = $viewerAddressHashes[0].ToLowerInvariant()

$rawOverlay = Get-Content -LiteralPath $rawOverlayPath -Raw |
    ConvertFrom-Json
Assert-I06AttestationEqual `
    -Actual (Get-I06AttestationProperty $rawOverlay `
        'schema' 'Private overlay observation') `
    -Expected 'ese.v91.i06-overlay-path/v1' `
    -Context 'Private overlay observation schema'
Assert-I06AttestationEqual `
    -Actual (Get-I06AttestationProperty $rawOverlay `
        'case_id' 'Private overlay observation') `
    -Expected 'V91-I06' -Context 'Private overlay observation case ID'
$overlayPathObserved = ConvertTo-I06AttestationDateTimeOffset `
    -Value (Get-I06AttestationProperty $rawOverlay `
        'captured_at_utc' 'Private overlay observation') `
    -Context 'Private overlay observation capture time'
if ($overlayPathObserved -lt $viewerSessionStarted) {
    throw 'Private overlay observation predates the viewer session.'
}
Assert-I06AttestationEqual `
    -Actual (Get-I06AttestationProperty $rawOverlay `
        'topology' 'Private overlay observation') `
    -Expected 'T6' -Context 'Private overlay topology'
$transport = [string](Get-I06AttestationProperty $rawOverlay `
    'transport' 'Private overlay observation')
if ($transport -notmatch '(?i)\bTailscale\b' -or
    $transport -notmatch '(?i)\boverlay\b') {
    throw 'Private overlay observation does not identify Tailscale overlay.'
}
$addressFamily = [string](Get-I06AttestationProperty $rawOverlay `
    'address_family' 'Private overlay observation')
if ($addressFamily -notmatch '(?i)\bIPv6\b') {
    throw 'Private overlay observation does not identify IPv6.'
}
$publicIPv6 = Get-I06AttestationProperty $rawOverlay `
    'native_public_ipv6' 'Private overlay observation'
if ($publicIPv6 -isnot [bool] -or [bool]$publicIPv6) {
    throw 'Private overlay observation must explicitly deny native public IPv6.'
}

$rawCandidate = Get-I06AttestationProperty $rawOverlay `
    'candidate' 'Private overlay observation'
foreach ($identity in @(
    [pscustomobject]@{
        name = 'commit'
        actual = [string](Get-I06AttestationProperty $rawCandidate `
            'commit' 'Private overlay candidate')
        expected = $candidate.commit
    },
    [pscustomobject]@{
        name = 'emule.exe hash'
        actual = [string](Get-I06AttestationProperty $rawCandidate `
            'emule_sha256' 'Private overlay candidate')
        expected = $candidate.emule_sha256
    },
    [pscustomobject]@{
        name = 'ese-server.exe hash'
        actual = [string](Get-I06AttestationProperty $rawCandidate `
            'ese_server_sha256' 'Private overlay candidate')
        expected = $candidate.ese_server_sha256
    },
    [pscustomobject]@{
        name = 'BUILD_INFO.txt hash'
        actual = [string](Get-I06AttestationProperty $rawCandidate `
            'build_info_sha256' 'Private overlay candidate')
        expected = $candidate.build_info_sha256
    }
)) {
    Assert-I06AttestationEqual `
        -Actual $identity.actual.ToLowerInvariant() `
        -Expected $identity.expected `
        -Context "Private overlay candidate $($identity.name)"
}

$rawViewer = Get-I06AttestationProperty $rawOverlay `
    'viewer' 'Private overlay observation'
$rawSource = Get-I06AttestationProperty $rawOverlay `
    'source' 'Private overlay observation'
$rawViewerIPv6 = ConvertTo-I06AttestationIPv6 `
    -Value (Get-I06AttestationProperty $rawViewer `
        'tailscale_ipv6' 'Private overlay viewer') `
    -Context 'Private overlay viewer address'
$rawSourceIPv6 = ConvertTo-I06AttestationIPv6 `
    -Value (Get-I06AttestationProperty $rawSource `
        'tailscale_ipv6' 'Private overlay source') `
    -Context 'Private overlay source address'
if ($rawViewerIPv6.Equals($rawSourceIPv6)) {
    throw 'Private overlay observation contains identical endpoint addresses.'
}
$rawViewerHash = Get-LabStringSha256 `
    -Value $rawViewerIPv6.ToString().ToLowerInvariant()
$rawSourceHash = Get-LabStringSha256 `
    -Value $rawSourceIPv6.ToString().ToLowerInvariant()
Assert-I06AttestationEqual -Actual $rawViewerHash `
    -Expected $viewerAddressHash `
    -Context 'Private overlay viewer versus route endpoint'
Assert-I06AttestationEqual -Actual $rawSourceHash `
    -Expected $sourceAddressHash `
    -Context 'Private overlay source versus session endpoint'
foreach ($stateName in @('online', 'active')) {
    $state = Get-I06AttestationProperty $rawSource `
        $stateName 'Private overlay source'
    if ($state -isnot [bool] -or -not [bool]$state) {
        throw "Private overlay source $stateName must be true."
    }
}

$rawObservedPath = Get-I06AttestationProperty $rawOverlay `
    'observed_path' 'Private overlay observation'
$pathKind = [string](Get-I06AttestationProperty $rawObservedPath `
    'kind' 'Private overlay path')
if ($pathKind -notmatch '(?i)\bDERP\b') {
    throw 'Private overlay path does not explicitly identify DERP.'
}
$derpRegion = [string](Get-I06AttestationProperty $rawObservedPath `
    'region' 'Private overlay path')
if ([string]::IsNullOrWhiteSpace($derpRegion) -or
    $derpRegion -notmatch '^[A-Za-z0-9_-]{1,32}$') {
    throw 'Private overlay DERP region is missing or malformed.'
}
$direct = Get-I06AttestationProperty $rawObservedPath `
    'direct' 'Private overlay path'
if ($direct -isnot [bool] -or [bool]$direct) {
    throw 'Private overlay path must explicitly record direct=false.'
}
$pongs = @(Get-I06AttestationProperty $rawObservedPath `
    'pongs' 'Private overlay path')
if ($pongs.Count -lt 1 -or
    @($pongs | Where-Object {
        [string]$_ -match '(?i)\bDERP\s*\('
    }).Count -lt 1) {
    throw 'Private overlay observation contains no DERP path sample.'
}

$privateBindings = @(
    [pscustomobject][ordered]@{
        role = 'viewer_session'
        schema = 'ese.v91.i06-isolated-viewer/v1'
        sha256 = Get-LabSha256 -Path $sessionPath
    },
    [pscustomobject][ordered]@{
        role = 'startup_route'
        schema = 'ese.v91.i06-isolated-route-start/v1'
        sha256 = Get-LabSha256 -Path $routePath
    },
    [pscustomobject][ordered]@{
        role = 'raw_overlay_observation'
        schema = 'ese.v91.i06-overlay-path/v1'
        sha256 = Get-LabSha256 -Path $rawOverlayPath
    },
    [pscustomobject][ordered]@{
        role = 'source_ready_private_capture'
        media_type = 'image/jpeg'
        sha256 = Get-LabSha256 -Path $sourceReadyCapturePath
    }
)

$attestation = [ordered]@{
    schema = 'ese.v91.i06-sanitized-operator-attestation/v1'
    case_id = 'V91-I06'
    attested_at_utc = Get-LabUtcTimestamp
    attestor = [ordered]@{
        kind = 'human_operator'
        identity_disclosed = $false
        cryptographically_signed = $false
        assurance = 'explicit-operator-confirmation'
    }
    candidate = [ordered]@{
        version = $candidate.version
        commit = $candidate.commit
        emule_sha256 = $candidate.emule_sha256
        ese_server_sha256 = $candidate.ese_server_sha256
        build_info_sha256 = $candidate.build_info_sha256
    }
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
        observed_path = [ordered]@{
            kind = 'DERP'
            region = $derpRegion
            direct = $false
        }
        native_public_ipv6 = $false
    }
    operator_observations = [ordered]@{
        viewer_execution_observed = $true
        source_interactive_rdp_observed = $true
        source_ready_observed = $true
        source_candidate_identity_observed_in_ready = $true
        source_and_viewer_confirmed_separate = $true
    }
    observation_times = [ordered]@{
        viewer_session_started_at_utc = $viewerSessionStarted.ToString('o')
        startup_route_captured_at_utc = $startupRouteCaptured.ToString('o')
        overlay_path_observed_at_utc = $overlayPathObserved.ToString('o')
    }
    endpoint_bindings = [ordered]@{
        viewer_address_sha256 = $viewerAddressHash
        source_address_sha256 = $sourceAddressHash
        raw_addresses_embedded = $false
    }
    private_evidence_bindings = $privateBindings
    limitations = @(
        'Physical-host facts are operator-attested, not automatically detected.',
        'The attestation is not cryptographically signed.',
        'T6 proves IPv6 overlay transport, not native public IPv6 reachability.'
    )
    privacy = [ordered]@{
        public_safe = $true
        hostnames_embedded = $false
        network_addresses_embedded = $false
        stream_keys_embedded = $false
        process_ids_embedded = $false
        filesystem_paths_embedded = $false
        private_evidence_contents_embedded = $false
    }
}

$written = Write-LabJson -Value $attestation -Path $attestationPath
Write-Host "Sanitized V91-I06 operator attestation written: $written" `
    -ForegroundColor Green
$attestation | ConvertTo-Json -Depth 12
