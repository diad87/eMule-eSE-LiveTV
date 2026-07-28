Set-StrictMode -Version 2.0

function Get-I05T1Constants {
    return [pscustomobject][ordered]@{
        case_id = 'V91-I05'
        topology = 'T1'
        candidate_version = '9.1.0-rc.2'
        candidate_commit =
            '08aa6521f7d7907edb3584266abc3a9e31693161'
        candidate_emule_sha256 =
            '55c5aa0e968b25330720cfb7f622cbc28ea9875365145333cbcf9d9585c1c44a'
        candidate_ese_server_sha256 =
            'eeceef0f0dbe427f3667c033e2b653fc69e432abcc3e8afaf996840a7315e568'
        candidate_build_info_sha256 =
            '7c87f77268030c2b4da40c6da8c960f968b4e1a033c9987b64e45c49cf4b5915'
        candidate_zip_sha256 =
            '5f17af0edbdda9e1fcc165d2e2f8a33910b40f856343934b970db24259cf3590'
        candidate_zip_bytes = [Int64]212025531
        fixture_seed_sha256 =
            'd1e2a156261ecc675081943197a85f08f2868784a0af499171ede89353edad31'
        fixture_name = 'v91-i05-canonical-4294967296.bin'
        fixture_bytes = [Int64]4294967296
        fixture_sha256 =
            '1016d6f63ae1649a879a7c0de30865ed132deb37b1c3b2bc9ca004c88feee26c'
        fixture_ed2k = '796A95E75DF8E78D54A57CDEA1FEDE84'
        source_tcp_port = 7862
        source_udp_port = 7872
        source_web_port = 7911
        source_probe_port = 7912
        downloader_tcp_port = 7962
        downloader_udp_port = 7972
        downloader_web_port = 8011
        downloader_control_port = 8012
        downloader_min_free_bytes = [Int64]10737418240
        capture_packet_size = 256
        capture_file_mib = 2048
        evidence_bundle_max_bytes = 524288
        evidence_bundle_max_entries = 11
        evidence_bundle_max_expanded_bytes = 4194304
        forbidden_interface_pattern =
            '(?i)Tailscale|Cloudflare|WARP|vEthernet|Hyper-V'
        config_file = 'V91-I05-T1-CONFIG.json'
        ready_file = 'READY-V91-I05-T1.json'
        command_file = 'COMMAND-V91-I05-T1.json'
        started_file = 'STARTED-V91-I05-T1.json'
        complete_file = 'COMPLETE-V91-I05-T1.json'
        cleanup_file = 'CLEANUP-V91-I05-T1.json'
    }
}

function Expand-I05ExactRc2Zip {
    param(
        [Parameter(Mandatory = $true)][string]$ZipPath,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $constants = Get-I05T1Constants
    if (-not (Test-Path -LiteralPath $ZipPath -PathType Leaf)) {
        throw 'The pinned RC2 ZIP is missing.'
    }
    $zip = (Resolve-Path -LiteralPath $ZipPath).Path
    $zipItem = Get-Item -LiteralPath $zip -Force
    if (($zipItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The pinned RC2 ZIP cannot be a reparse point.'
    }
    if ([Int64]$zipItem.Length -ne $constants.candidate_zip_bytes) {
        throw 'The pinned RC2 ZIP byte length does not match.'
    }
    $zipHash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).
        Hash.ToLowerInvariant()
    if ($zipHash -cne $constants.candidate_zip_sha256) {
        throw 'The pinned RC2 ZIP SHA-256 does not match.'
    }

    $target = [IO.Path]::GetFullPath($Destination)
    if (Test-Path -LiteralPath $target) {
        throw 'The exact RC2 extraction destination must be new.'
    }
    $parent = Split-Path -Parent $target
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw 'The exact RC2 extraction parent does not exist.'
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($zip)
    try {
        foreach ($entry in $archive.Entries) {
            $entryPath = [IO.Path]::GetFullPath(
                (Join-Path $target $entry.FullName))
            if (-not $entryPath.StartsWith(
                    ($target.TrimEnd('\', '/') + '\'),
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw 'The pinned RC2 ZIP contains an escaping path.'
            }
        }
    } finally {
        $archive.Dispose()
    }
    $null = New-Item -ItemType Directory -Path $target
    try {
        [IO.Compression.ZipFile]::ExtractToDirectory($zip, $target)
        foreach ($item in Get-ChildItem -LiteralPath $target `
                -Recurse -Force) {
            if (($item.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'The exact RC2 extraction contains a reparse point.'
            }
        }
        $candidate = Get-LabCandidateInfo -PackagePath $target `
            -ExpectedCommit $constants.candidate_commit
        if ([string]$candidate.version -cne
                $constants.candidate_version -or
            [string]$candidate.emule_sha256 -cne
                $constants.candidate_emule_sha256 -or
            [string]$candidate.ese_server_sha256 -cne
                $constants.candidate_ese_server_sha256 -or
            [string]$candidate.build_info_sha256 -cne
                $constants.candidate_build_info_sha256) {
            throw 'The extracted RC2 candidate identity does not match.'
        }
        return [pscustomobject][ordered]@{
            zip_path = $zip
            zip_bytes = [Int64]$zipItem.Length
            zip_sha256 = $zipHash
            package_path = $target
            candidate = $candidate
        }
    } catch {
        if (Test-Path -LiteralPath $target -PathType Container) {
            Remove-Item -LiteralPath $target -Recurse -Force `
                -ErrorAction SilentlyContinue
        }
        throw
    }
}

function Get-I05RequiredProperty {
    param(
        [Parameter(Mandatory = $true)][object]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        throw "$Context is missing required property '$Name'."
    }
    return $property.Value
}

function Get-I05HostIdSha256 {
    $machineGuid = [string](Get-ItemProperty `
        -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' `
        -Name 'MachineGuid' -ErrorAction Stop).MachineGuid
    $parsed = [Guid]::Empty
    if (-not [Guid]::TryParse($machineGuid, [ref]$parsed)) {
        throw 'Windows MachineGuid is missing or invalid.'
    }
    $canonical = $parsed.ToString('N').ToLowerInvariant()
    return Get-LabStringSha256 -Value $canonical
}

function Get-I05EffectiveRouteEvidence {
    param([Parameter(Mandatory = $true)][string]$RemoteIPv4)

    $remote = ConvertTo-I05CanonicalIPv4 -Value $RemoteIPv4 `
        -Context 'Effective-route destination'
    $selection = @(Find-NetRoute -RemoteIPAddress $remote `
        -ErrorAction Stop)
    $addresses = @($selection | Where-Object {
        [string]$_.CimClass.CimClassName -eq 'MSFT_NetIPAddress' -and
        $_.PSObject.Properties['IPAddress']
    })
    $routes = @($selection | Where-Object {
        [string]$_.CimClass.CimClassName -eq 'MSFT_NetRoute' -and
        $_.PSObject.Properties['DestinationPrefix']
    })
    if ($addresses.Count -ne 1 -or $routes.Count -ne 1) {
        throw 'Find-NetRoute did not return one address/route pair.'
    }
    $address = $addresses[0]
    $route = $routes[0]
    $source = ConvertTo-I05CanonicalIPv4 -Value $address.IPAddress `
        -Context 'Effective-route source'
    if ([int]$address.InterfaceIndex -ne [int]$route.InterfaceIndex) {
        throw 'Find-NetRoute address and route use different interfaces.'
    }
    $parts = ([string]$route.DestinationPrefix).Split('/')
    if ($parts.Count -ne 2 -or
        -not (Test-I05Ipv4SameSubnet -Left $remote -Right $parts[0] `
            -PrefixLength ([int]$parts[1]))) {
        throw 'Find-NetRoute selected prefix does not contain destination.'
    }
    return [pscustomobject][ordered]@{
        source_address = $source
        interface_index = [int]$address.InterfaceIndex
        next_hop = [string]$route.NextHop
        destination_prefix = [string]$route.DestinationPrefix
        address_object_class = [string]$address.CimClass.CimClassName
        route_object_class = [string]$route.CimClass.CimClassName
    }
}

function Assert-I05ExactText {
    param(
        [AllowEmptyString()][string]$Actual,
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)][string]$Context,
        [switch]$IgnoreCase
    )

    $comparison = if ($IgnoreCase) {
        [StringComparison]::OrdinalIgnoreCase
    } else {
        [StringComparison]::Ordinal
    }
    if (-not [string]::Equals(
            $Actual, $Expected, $comparison)) {
        throw "$Context does not match the exact V91-I05 value."
    }
}

function Assert-I05True {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if ($Value -isnot [bool] -or -not [bool]$Value) {
        throw "$Context must be the JSON boolean true."
    }
}

function Assert-I05False {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if ($Value -isnot [bool] -or [bool]$Value) {
        throw "$Context must be the JSON boolean false."
    }
}

function Assert-I05ApiNetworksOff {
    param(
        [Parameter(Mandatory = $true)][object]$Status,
        [Parameter(Mandatory = $true)][string]$Context
    )

    foreach ($name in @(
        'kad_connected',
        'kad6_running',
        'kad6_connected'
    )) {
        Assert-I05False -Value (Get-I05RequiredProperty `
            -Object $Status -Name $name -Context $Context) `
            -Context "$Context.$name"
    }
}

function Assert-I05Sha256 {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $text = ([string]$Value).Trim().ToLowerInvariant()
    if ($text -notmatch '^[0-9a-f]{64}$') {
        throw "$Context is not a canonical SHA-256 value."
    }
    return $text
}

function Assert-I05Nonce {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $text = ([string]$Value).Trim().ToLowerInvariant()
    if ($text -notmatch '^[0-9a-f]{32}$') {
        throw "$Context is not a canonical 32-hex nonce."
    }
    return $text
}

function ConvertTo-I05UtcTimestamp {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse(
            [string]$Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal,
            [ref]$parsed)) {
        throw "$Context is not a valid timestamp."
    }
    return $parsed.ToUniversalTime()
}

function ConvertTo-I05CanonicalIPv4 {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $parsed = $null
    if (-not [Net.IPAddress]::TryParse(
            ([string]$Value).Trim(), [ref]$parsed) -or
        $parsed.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork) {
        throw "$Context is not an IPv4 address."
    }
    return $parsed.ToString()
}

function ConvertTo-I05CanonicalIPv6 {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $text = ([string]$Value).Trim().Trim('[', ']')
    $text = $text.Split('%')[0]
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($text, [ref]$parsed) -or
        $parsed.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetworkV6) {
        throw "$Context is not an IPv6 address."
    }
    return $parsed.ToString().ToLowerInvariant()
}

function Test-I05SamePath {
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )

    try {
        $leftFull = [IO.Path]::GetFullPath(
            [Environment]::ExpandEnvironmentVariables($Left)).
            TrimEnd([char[]]@('\', '/'))
        $rightFull = [IO.Path]::GetFullPath(
            [Environment]::ExpandEnvironmentVariables($Right)).
            TrimEnd([char[]]@('\', '/'))
        return [string]::Equals(
            $leftFull, $rightFull,
            [StringComparison]::OrdinalIgnoreCase)
    } catch {
        return $false
    }
}

function Test-I05PathContained {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )

    try {
        $rootFull = [IO.Path]::GetFullPath($Root).
            TrimEnd([char[]]@('\', '/'))
        $pathFull = [IO.Path]::GetFullPath($Path)
        $prefix = $rootFull +
            [IO.Path]::DirectorySeparatorChar
        return $pathFull.StartsWith(
            $prefix, [StringComparison]::OrdinalIgnoreCase)
    } catch {
        return $false
    }
}

function Test-I05Ipv4SameSubnet {
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 32)][int]$PrefixLength
    )

    $leftAddress = [Net.IPAddress]::Parse(
        (ConvertTo-I05CanonicalIPv4 -Value $Left -Context 'Left IPv4'))
    $rightAddress = [Net.IPAddress]::Parse(
        (ConvertTo-I05CanonicalIPv4 -Value $Right -Context 'Right IPv4'))
    $leftBytes = $leftAddress.GetAddressBytes()
    $rightBytes = $rightAddress.GetAddressBytes()
    $fullBytes = [int][Math]::Floor($PrefixLength / 8)
    $remainingBits = $PrefixLength % 8
    for ($index = 0; $index -lt $fullBytes; $index++) {
        if ($leftBytes[$index] -ne $rightBytes[$index]) {
            return $false
        }
    }
    if ($remainingBits -gt 0) {
        $mask = [byte](
            (0xff -shl (8 - $remainingBits)) -band 0xff)
        if (($leftBytes[$fullBytes] -band $mask) -ne
            ($rightBytes[$fullBytes] -band $mask)) {
            return $false
        }
    }
    return $true
}

function Assert-I05CandidateContract {
    param(
        [Parameter(Mandatory = $true)][object]$Candidate,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $constants = Get-I05T1Constants
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $Candidate -Name 'version' -Context $Context)) `
        -Expected $constants.candidate_version `
        -Context "$Context.version"
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $Candidate -Name 'commit' -Context $Context)) `
        -Expected $constants.candidate_commit `
        -Context "$Context.commit" -IgnoreCase
    Assert-I05False -Value (Get-I05RequiredProperty `
        -Object $Candidate -Name 'dirty' -Context $Context) `
        -Context "$Context.dirty"

    $hashChecks = [ordered]@{
        emule_sha256 = $constants.candidate_emule_sha256
        ese_server_sha256 =
            $constants.candidate_ese_server_sha256
        build_info_sha256 =
            $constants.candidate_build_info_sha256
    }
    foreach ($name in $hashChecks.Keys) {
        $actual = Assert-I05Sha256 -Value (
            Get-I05RequiredProperty -Object $Candidate `
                -Name $name -Context $Context
        ) -Context "$Context.$name"
        Assert-I05ExactText -Actual $actual `
            -Expected $hashChecks[$name] `
            -Context "$Context.$name" -IgnoreCase
    }
    $zipHash = Assert-I05Sha256 -Value (
        Get-I05RequiredProperty -Object $Candidate `
            -Name 'zip_sha256' -Context $Context
    ) -Context "$Context.zip_sha256"
    Assert-I05ExactText -Actual $zipHash `
        -Expected $constants.candidate_zip_sha256 `
        -Context "$Context.zip_sha256" -IgnoreCase
    if ([Int64](Get-I05RequiredProperty -Object $Candidate `
            -Name 'zip_bytes' -Context $Context) -ne
        $constants.candidate_zip_bytes) {
        throw "$Context.zip_bytes is not the exact RC2 ZIP length."
    }
}

function Read-I05JsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Context,
        [ValidateRange(16, 4194304)][int]$MaximumBytes = 1048576
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Context does not exist."
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Context cannot be a reparse point."
    }
    if ($item.Length -lt 2 -or $item.Length -gt $MaximumBytes) {
        throw "$Context has an invalid size."
    }
    $raw = [IO.File]::ReadAllText($item.FullName)
    $document = $raw | ConvertFrom-Json
    if ($null -eq $document -or $document -is [Array]) {
        throw "$Context is not one JSON object."
    }
    return [pscustomobject][ordered]@{
        path = $item.FullName
        raw = $raw
        document = $document
    }
}

function Wait-I05JsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Context,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 86400)][int]$TimeoutSeconds,
        [ValidateRange(50, 5000)][int]$PollMilliseconds = 250
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastError = $null
    do {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            try {
                return Read-I05JsonFile -Path $Path -Context $Context
            } catch {
                $lastError = $_.Exception.Message
            }
        }
        Start-Sleep -Milliseconds $PollMilliseconds
    } while ([DateTime]::UtcNow -lt $deadline)

    if ($lastError) {
        throw "$Context did not stabilize before timeout: $lastError"
    }
    throw "$Context was not supplied before timeout."
}
