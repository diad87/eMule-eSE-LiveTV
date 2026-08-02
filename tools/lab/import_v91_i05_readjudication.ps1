[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')]
    [string]$AgentIPv4,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$RemoteRun,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$ExpectedCompleteSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$ExpectedReportSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$ExpectedHarnessCommit,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{32}$')]
    [string]$ExpectedNonce,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')]
    [string]$H3IPv4,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')]
    [string]$SourceIPv4,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

function Get-LocalBytesSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-RemoteBytes {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Token
    )
    $response = & $controller -Command download `
        -AgentIPv4 $AgentIPv4 -Token $Token -RemotePath $Path `
        -Length 786432 -ResponseTimeoutMilliseconds 30000
    $bytes = [Convert]::FromBase64String(
        [string]$response.content_base64)
    if ([Int64]$response.offset -ne 0 -or
        [Int64]$response.file_bytes -ne $bytes.Length -or
        [Int64]$response.bytes -ne $bytes.Length -or
        -not [bool]$response.eof) {
        throw "La descarga de '$Path' no fue atómica/completa."
    }
    return $bytes
}

function ConvertFrom-StrictJsonBytes {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Label
    )
    try {
        $utf8 = New-Object Text.UTF8Encoding($false, $true)
        return $utf8.GetString($Bytes) | ConvertFrom-Json
    } catch {
        throw "$Label no contiene JSON UTF-8 válido."
    }
}

$controller = Join-Path $PSScriptRoot 'control_ese_lab_agent.ps1'
$sourceRunner = Join-Path $PSScriptRoot 'run_v91_i05_t1_source.ps1'
$tokenPath = Join-Path $env:LOCALAPPDATA `
    'eSE-Lab-Controller\agent-token.dpapi'
if (-not (Test-Path -LiteralPath $tokenPath -PathType Leaf)) {
    throw 'No existe la credencial DPAPI local del controlador.'
}
$cipher = Get-Content -LiteralPath $tokenPath -Raw
$secure = ConvertTo-SecureString $cipher
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    if ($token -notmatch '^[0-9a-fA-F]{64}$') {
        throw 'La credencial DPAPI del controlador no es válida.'
    }

    $documents = [ordered]@{
        complete = "$RemoteRun/COMPLETE-READJUDICATED-V91-I05-T1.json"
        report = "$RemoteRun/READJUDICATION-V91-I05-T1.json"
        ready = "$RemoteRun/READY-V91-I05-T1.json"
        cleanup = "$RemoteRun/CLEANUP-V91-I05-T1.json"
        failure = "$RemoteRun/evidence/FAILURE-V91-I05-T1.json"
    }
    $downloaded = @{}
    foreach ($entry in $documents.GetEnumerator()) {
        $downloaded[$entry.Key] = Get-RemoteBytes `
            -Path $entry.Value -Token $token
    }
} finally {
    if ($pointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

$completeHash = Get-LocalBytesSha256 -Bytes $downloaded.complete
$reportHash = Get-LocalBytesSha256 -Bytes $downloaded.report
if ($completeHash -cne $ExpectedCompleteSha256.ToLowerInvariant()) {
    throw 'El hash del COMPLETE remoto cambió durante la importación.'
}
if ($reportHash -cne $ExpectedReportSha256.ToLowerInvariant()) {
    throw 'El hash del informe remoto cambió durante la importación.'
}

$complete = ConvertFrom-StrictJsonBytes -Bytes $downloaded.complete `
    -Label 'COMPLETE readjudicado'
$report = ConvertFrom-StrictJsonBytes -Bytes $downloaded.report `
    -Label 'Informe de readjudicación'
$ready = ConvertFrom-StrictJsonBytes -Bytes $downloaded.ready `
    -Label 'READY original'
$cleanup = ConvertFrom-StrictJsonBytes -Bytes $downloaded.cleanup `
    -Label 'CLEANUP original'
$failure = ConvertFrom-StrictJsonBytes -Bytes $downloaded.failure `
    -Label 'FAILURE original'

$nonce = [string]$complete.nonce
if ($nonce -cne $ExpectedNonce.ToLowerInvariant() -or
    [string]$complete.status -cne 'PASS' -or
    [string]$complete.readjudication.harness_commit -cne
        $ExpectedHarnessCommit -or
    [string]$complete.readjudication.original_failure_sha256 -cne
        (Get-LocalBytesSha256 -Bytes $downloaded.failure) -or
    -not [bool]$complete.readjudication.raw_evidence_reused -or
    [bool]$complete.readjudication.product_reexecuted -or
    [string]$report.complete_sha256 -cne $completeHash -or
    [string]$report.harness_commit -cne $ExpectedHarnessCommit -or
    [string]$cleanup.status -cne 'CLEANUP_COMPLETE' -or
    -not [bool]$cleanup.cleanup_complete -or
    [string]$failure.status -cne 'LAB_BLOCKED' -or
    [string]$failure.phase -cne 'pktmon_complete') {
    throw 'La cadena de procedencia de la readjudicación no es exacta.'
}

if (Test-Path -LiteralPath $OutputRoot) {
    throw 'El directorio central de importación ya existe.'
}
$null = New-Item -ItemType Directory -Path $OutputRoot
$inputRoot = New-Item -ItemType Directory `
    -Path (Join-Path $OutputRoot 'remote-documents')
$evidenceRoot = New-Item -ItemType Directory `
    -Path (Join-Path $OutputRoot 'validated-evidence')
foreach ($entry in $documents.GetEnumerator()) {
    $name = Split-Path -Leaf $entry.Value
    [IO.File]::WriteAllBytes(
        (Join-Path $inputRoot.FullName $name),
        [byte[]]$downloaded[$entry.Key])
}

$previousLibraryOnly = $env:ESE_V91_I05_SOURCE_LIBRARY_ONLY
try {
    $env:ESE_V91_I05_SOURCE_LIBRARY_ONLY = '1'
    . $sourceRunner -CandidateZipPath 'library-only' `
        -FixturePath 'library-only' `
        -ExpectedFixtureSha256 ('0' * 64) `
        -H3IPv4 $H3IPv4
} finally {
    $env:ESE_V91_I05_SOURCE_LIBRARY_ONLY = $previousLibraryOnly
}

$remote = [pscustomobject][ordered]@{
    host_id_sha256 = [string]$ready.host.host_id_sha256
    ipv4_address = [string]$ready.network.ipv4.address
    ipv4_address_sha256 = [string]$ready.network.ipv4.address_sha256
    ipv4_prefix_length = [int]$ready.network.ipv4.prefix_length
    interface_id = [string]$ready.network.ipv4.interface_id
    process_id = [int]$ready.node.process_id
    capture_intent_sha256 = [string]$ready.capture.intent_sha256
    component_guid_sha256 =
        [string]$ready.capture.component_mapping.interface_guid_sha256
    primary_component_id =
        [Int64]$ready.capture.component_mapping.primary_id
    secondary_component_ids =
        @($ready.capture.component_mapping.secondary_ids)
    mapping_key_sha256 =
        [string]$ready.capture.component_mapping.mapping_key_sha256
    inventory_pre_sha256 =
        [string]$ready.capture.component_mapping.inventories.pre_sha256
    inventory_armed_sha256 =
        [string]$ready.capture.component_mapping.inventories.armed_sha256
    ready_at_utc = [string]$ready.created_at_utc
}
$observedPorts = @(
    $complete.socket_proof.observed_ephemeral_ports |
        ForEach-Object { [int]$_ }
)
$validation = Assert-I05SourceRemoteComplete `
    -Complete $complete -Nonce $nonce -Remote $remote `
    -SourceIPv4 $SourceIPv4 `
    -ObservedRemotePorts $observedPorts `
    -EvidenceRoot $evidenceRoot.FullName
if ([string]$validation.status -cne 'PASS' -or
    [int]$validation.retained_raw_count -ne 12 -or
    [int]$validation.entry_count -ne 11) {
    throw 'La validación central no produjo el expediente completo esperado.'
}

$centralReport = [ordered]@{
    schema = 'ese.v91.i05.t1-central-readjudication/v1'
    case_id = 'V91-I05'
    status = 'PASS'
    nonce = $nonce
    validated_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    candidate = $complete.candidate
    source_ipv4 = $SourceIPv4
    downloader_ipv4 = [string]$ready.network.ipv4.address
    complete_sha256 = $completeHash
    remote_report_sha256 = $reportHash
    original_failure_sha256 =
        Get-LocalBytesSha256 -Bytes $downloaded.failure
    cleanup_sha256 = Get-LocalBytesSha256 -Bytes $downloaded.cleanup
    harness_commit = $ExpectedHarnessCommit
    evidence_bundle_sha256 = [string]$validation.sha256
    evidence_manifest_sha256 = [string]$validation.manifest_sha256
    evidence_entry_count = [int]$validation.entry_count
    retained_raw_count = [int]$validation.retained_raw_count
    observed_ephemeral_ports = @($validation.observed_ephemeral_ports)
    raw_evidence_reused = $true
    product_reexecuted = $false
}
$centralPath = Join-Path $OutputRoot `
    'CENTRAL-READJUDICATION-V91-I05-T1.json'
$utf8 = New-Object Text.UTF8Encoding($false)
[IO.File]::WriteAllText(
    $centralPath,
    ($centralReport | ConvertTo-Json -Depth 12),
    $utf8)

[pscustomobject][ordered]@{
    status = 'PASS'
    case_id = 'V91-I05'
    nonce = $nonce
    central_report = $centralPath
    central_report_sha256 = (
        Get-FileHash -LiteralPath $centralPath -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    complete_sha256 = $completeHash
    evidence_bundle_sha256 = [string]$validation.sha256
    evidence_entry_count = [int]$validation.entry_count
    retained_raw_count = [int]$validation.retained_raw_count
} | ConvertTo-Json -Depth 8
