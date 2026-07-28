[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$JobRequestPath
)

$ErrorActionPreference = 'Stop'
$jobRoot = Split-Path -Parent ([IO.Path]::GetFullPath($JobRequestPath))
$jobsRoot = Split-Path -Parent $jobRoot
$kitRoot = Split-Path -Parent $jobsRoot
$activePath = Join-Path $kitRoot 'ACTIVE-V91-I05-T1.json'
$candidateSha =
    '55c5aa0e968b25330720cfb7f622cbc28ea9875365145333cbcf9d9585c1c44a'

$jobRequest = Get-Content -LiteralPath $JobRequestPath -Raw |
    ConvertFrom-Json
$nonce = [string]$jobRequest.request.campaign_nonce
if ($nonce -notmatch '^[0-9a-f]{32}$') {
    throw 'campaign_nonce debe ser 32hex lowercase.'
}

$roleTokens = @(
    'in-tcp-v4-not-h1',
    'in-tcp-v6-all',
    'in-udp-v4-all',
    'in-udp-v6-all',
    'out-tcp-v4-not-h1-loopback',
    'out-tcp-v4-loopback-non-api-local-ports',
    'out-tcp-v4-h1-wrong-ports',
    'out-tcp-v6-all',
    'out-udp-v4-all',
    'out-udp-v6-all'
)
$ruleNames = @(
    "eSE-V91-I05-H3-$nonce",
    "eSE-V91-I05-H3-Control-$nonce"
)
$ruleNames += @($roleTokens | ForEach-Object {
    "eSE-V91-I05-H3-Isolation-$nonce-$_"
})
if (Test-Path -LiteralPath $activePath -PathType Leaf) {
    try {
        $active = Get-Content -LiteralPath $activePath -Raw |
            ConvertFrom-Json
        $ruleNames += @(
            [string]$active.firewall_rule_name
            [string]$active.control_firewall_rule_name
        )
        $ruleNames += @($active.containment.rules | ForEach-Object {
            [string]$_.name
        })
    } catch {
        throw "ACTIVE no se puede auditar: $($_.Exception.Message)"
    }
}
$ruleNames = @($ruleNames | Where-Object {
    -not [string]::IsNullOrWhiteSpace([string]$_)
} | Sort-Object -Unique)

$ownedRules = [Collections.Generic.List[object]]::new()
foreach ($ruleName in $ruleNames) {
    try {
        $matches = @(Get-NetFirewallRule -PolicyStore ActiveStore `
            -Name $ruleName -ErrorAction Stop)
        foreach ($rule in $matches) {
            $ownedRules.Add([pscustomobject][ordered]@{
                name = [string]$rule.Name
                display_name = [string]$rule.DisplayName
            })
        }
    } catch {
        $notFound = $_.CategoryInfo.Category -eq 'ObjectNotFound' -or
            $_.FullyQualifiedErrorId -match
                'NoMatching.*GetNetFirewallRule|ObjectNotFound'
        if (-not $notFound) {
            throw "No se pudo consultar la regla exacta '$ruleName': $($_.Exception.Message)"
        }
    }
}
$candidateProcesses = @()
foreach ($process in @(Get-CimInstance Win32_Process -Filter `
        "Name='emule.exe'" -ErrorAction Stop)) {
    $path = [string]$process.ExecutablePath
    if (-not [string]::IsNullOrWhiteSpace($path) -and
        $path.StartsWith(
            $kitRoot.TrimEnd('\') + '\',
            [StringComparison]::OrdinalIgnoreCase)) {
        $candidateProcesses += [pscustomobject]@{
            process_id = [int]$process.ProcessId
            executable_sha256 = (
                Get-FileHash -LiteralPath $path -Algorithm SHA256
            ).Hash.ToLowerInvariant()
        }
    }
}

$pktmonOut = Join-Path $jobRoot 'pktmon-filter-list.out.txt'
$pktmonErr = Join-Path $jobRoot 'pktmon-filter-list.err.txt'
$pktmon = Start-Process -FilePath "$env:SystemRoot\System32\pktmon.exe" `
    -ArgumentList @('filter', 'list') -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput $pktmonOut -RedirectStandardError $pktmonErr
$pktmonCompleted = $pktmon.WaitForExit(15000)
if (-not $pktmonCompleted) {
    Stop-Process -Id $pktmon.Id -Force -ErrorAction SilentlyContinue
}
$pktmonFilters = if ($pktmonCompleted) {
    @(
        if (Test-Path -LiteralPath $pktmonOut -PathType Leaf) {
            Get-Content -LiteralPath $pktmonOut
        }
        if (Test-Path -LiteralPath $pktmonErr -PathType Leaf) {
            Get-Content -LiteralPath $pktmonErr
        }
    ) -join "`n"
} else {
    ''
}
$pktmonOwnedNames = @(
    0..4 | ForEach-Object {
        switch ($_) {
            0 { "ese-i05-$($nonce.Substring(0, 8))-v4-data" }
            1 { "ese-i05-$($nonce.Substring(0, 8))-v6-src-tcp" }
            2 { "ese-i05-$($nonce.Substring(0, 8))-v6-dst-tcp" }
            3 { "ese-i05-$($nonce.Substring(0, 8))-v6-src-udp" }
            4 { "ese-i05-$($nonce.Substring(0, 8))-v6-dst-udp" }
        }
    }
)
$pktmonOwnedPresent = $false
if ($pktmonCompleted) {
    $pktmonOwnedPresent = @($pktmonOwnedNames | Where-Object {
        $pktmonFilters.IndexOf(
            $_, [StringComparison]::OrdinalIgnoreCase) -ge 0
    }).Count -gt 0
}

$recentRuns = @(Get-ChildItem (Join-Path $kitRoot 'runs') -Directory |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 3 |
    ForEach-Object {
        [pscustomobject]@{
            name = $_.Name
            cleanup_exists = Test-Path (
                Join-Path $_.FullName 'CLEANUP-V91-I05-T1.json'
            )
            failure_exists = Test-Path (
                Join-Path $_.FullName 'evidence\FAILURE-V91-I05-T1.json'
            )
        }
    })

$clean = -not (Test-Path $activePath) -and
    $ownedRules.Count -eq 0 -and
    $candidateProcesses.Count -eq 0 -and
    $pktmonCompleted -and
    -not $pktmonOwnedPresent

[pscustomobject][ordered]@{
    status = if ($clean) {
        'CLEAN'
    } elseif (-not $pktmonCompleted) {
        'UNKNOWN'
    } else {
        'DIRTY'
    }
    campaign_nonce = $nonce
    active_exists = Test-Path $activePath
    owned_rule_count = $ownedRules.Count
    owned_rules = $ownedRules.ToArray()
    candidate_process_count = $candidateProcesses.Count
    candidate_processes = $candidateProcesses
    expected_candidate_sha256 = $candidateSha
    pktmon_query_completed = $pktmonCompleted
    pktmon_owned_filter_present = $pktmonOwnedPresent
    recent_runs = $recentRuns
} | ConvertTo-Json -Depth 6 -Compress
