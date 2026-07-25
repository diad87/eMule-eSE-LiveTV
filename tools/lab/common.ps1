Set-StrictMode -Version 2.0

function Get-LabUtcTimestamp {
    return [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
}

function Get-LabFullPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    return [IO.Path]::GetFullPath($Path)
}

function New-LabDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = Get-LabFullPath -Path $Path
    if (-not (Test-Path -LiteralPath $fullPath -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $fullPath -Force
    }
    return $fullPath
}

function Get-LabSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Cannot hash missing file: $Path"
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-LabCandidateInfo {
    param(
        [Parameter(Mandatory = $true)][string]$PackagePath,
        [string]$ExpectedCommit = ''
    )

    $package = (Resolve-Path -LiteralPath $PackagePath).Path
    $buildInfoPath = Join-Path $package 'BUILD_INFO.txt'
    $binaryPath = Join-Path $package 'emule.exe'
    if (-not (Test-Path -LiteralPath $buildInfoPath -PathType Leaf)) {
        throw "Candidate package is missing BUILD_INFO.txt: $package"
    }
    if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
        throw "Candidate package is missing emule.exe: $package"
    }

    $values = @{}
    foreach ($line in Get-Content -LiteralPath $buildInfoPath) {
        if ($line -match '^\s*([^:]+):\s*(.*?)\s*$') {
            $values[$Matches[1].Trim().ToLowerInvariant()] = $Matches[2].Trim()
        }
    }
    $commit = [string]$values['commit']
    $release = [string]$values['release']
    $version = [string]$values['version']
    if ([string]::IsNullOrWhiteSpace($version) -and
        $release -match '^v0\.70b-eSE(.+)$') {
        $version = $Matches[1]
    }
    $dirty = [string]$values['dirty']
    if ($commit -notmatch '^[0-9a-fA-F]{40}$') {
        throw "BUILD_INFO.txt contains an invalid commit: '$commit'"
    }
    if ([string]::IsNullOrWhiteSpace($version)) {
        throw 'BUILD_INFO.txt does not contain a version'
    }
    if ($dirty -ne 'false') {
        throw "Candidate package is not from a clean worktree (dirty: $dirty)"
    }
    if ($ExpectedCommit -and
        $commit -ne $ExpectedCommit) {
        throw "Candidate commit mismatch: package=$commit expected=$ExpectedCommit"
    }

    return [pscustomobject][ordered]@{
        package_path = $package
        release = $release
        version = $version
        commit = $commit.ToLowerInvariant()
        emule_sha256 = Get-LabSha256 -Path $binaryPath
        ese_server_sha256 = Get-LabSha256 -Path (Join-Path $package 'ese-server.exe')
        build_info_sha256 = Get-LabSha256 -Path $buildInfoPath
    }
}

function Get-LabStringSha256 {
    param([AllowEmptyString()][string]$Value)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-LabInterfaceId {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [AllowEmptyString()][string]$Name = '',
        [AllowEmptyString()][string]$Description = ''
    )

    $identity = '{0}|{1}|{2}' -f $Id, $Name, $Description
    return (Get-LabStringSha256 -Value $identity).Substring(0, 12)
}

function Protect-LabText {
    param(
        [AllowNull()][string]$Value,
        [switch]$RedactAddresses
    )

    if ($null -eq $Value) { return $null }

    $result = $Value
    if ($RedactAddresses) {
        $result = [regex]::Replace(
            $result,
            '(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])',
            '<redacted-ipv4>'
        )
        $ipv6Evaluator = [Text.RegularExpressions.MatchEvaluator]{
            param($match)
            $candidate = $match.Value
            $colonCount = @($candidate.ToCharArray() | Where-Object { $_ -eq ':' }).Count
            $looksLikeAddress = $candidate.Contains('::') -or
                $candidate -match '(?i)[a-f]' -or
                $colonCount -ge 4
            $parsedAddress = $null
            if ($looksLikeAddress -and
                [Net.IPAddress]::TryParse($candidate, [ref]$parsedAddress) -and
                $parsedAddress.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
                return '<redacted-ipv6>'
            }
            return $candidate
        }
        $result = [regex]::Replace(
            $result,
            '(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])',
            $ipv6Evaluator
        )
    }
    return $result
}

function ConvertTo-LabSanitizedValue {
    param(
        [AllowNull()][object]$InputObject,
        [switch]$RedactAddresses
    )

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [string]) {
        return Protect-LabText -Value ([string]$InputObject) -RedactAddresses:$RedactAddresses
    }
    if ($InputObject -is [ValueType]) { return $InputObject }

    if ($InputObject -is [Collections.IDictionary]) {
        $output = [ordered]@{}
        foreach ($keyObject in $InputObject.Keys) {
            $key = [string]$keyObject
            if ($key -match '(?i)(password|passwd|secret|token|authorization|private.?key|cookie)') {
                $output[$key] = '<redacted>'
            } else {
                $output[$key] = ConvertTo-LabSanitizedValue `
                    -InputObject $InputObject[$keyObject] `
                    -RedactAddresses:$RedactAddresses
            }
        }
        return $output
    }

    if ($InputObject -is [Collections.IEnumerable]) {
        $items = @()
        foreach ($item in $InputObject) {
            $items += ,(ConvertTo-LabSanitizedValue `
                -InputObject $item `
                -RedactAddresses:$RedactAddresses)
        }
        return $items
    }

    $properties = @($InputObject.PSObject.Properties | Where-Object {
        $_.MemberType -eq 'NoteProperty' -or
        $_.MemberType -eq 'Property' -or
        $_.MemberType -eq 'AliasProperty'
    })
    if ($properties.Count -gt 0) {
        $output = [ordered]@{}
        foreach ($property in $properties) {
            if ($property.Name -match '(?i)(password|passwd|secret|token|authorization|private.?key|cookie)') {
                $output[$property.Name] = '<redacted>'
            } else {
                $output[$property.Name] = ConvertTo-LabSanitizedValue `
                    -InputObject $property.Value `
                    -RedactAddresses:$RedactAddresses
            }
        }
        return $output
    }

    return Protect-LabText -Value ([string]$InputObject) -RedactAddresses:$RedactAddresses
}

function Write-LabJson {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$Depth = 32
    )

    $fullPath = Get-LabFullPath -Path $Path
    $null = New-LabDirectory -Path (Split-Path -Parent $fullPath)
    $temporaryPath = '{0}.tmp-{1}-{2}' -f $fullPath, $PID, ([Guid]::NewGuid().ToString('N'))
    $encoding = New-Object Text.UTF8Encoding($false)
    try {
        $json = $Value | ConvertTo-Json -Depth $Depth
        [IO.File]::WriteAllText($temporaryPath, $json + [Environment]::NewLine, $encoding)
        Move-Item -LiteralPath $temporaryPath -Destination $fullPath -Force
    } finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
    return $fullPath
}

function Write-LabText {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $fullPath = Get-LabFullPath -Path $Path
    $null = New-LabDirectory -Path (Split-Path -Parent $fullPath)
    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($fullPath, $Value, $encoding)
    return $fullPath
}

function Get-LabAddressClass {
    param([Parameter(Mandatory = $true)][string]$Address)

    $withoutScope = $Address.Split('%')[0]
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($withoutScope, [ref]$parsed)) {
        return 'invalid'
    }

    if ($parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
        $bytes = $parsed.GetAddressBytes()
        if ($bytes[0] -eq 127) { return 'loopback-v4' }
        if ($bytes[0] -eq 10 -or
            ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 168)) {
            return 'private-v4'
        }
        if ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) {
            return 'cgnat-v4'
        }
        if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) { return 'linklocal-v4' }
        if ($bytes[0] -ge 224) { return 'special-v4' }
        return 'global-v4'
    }

    if ([Net.IPAddress]::IsLoopback($parsed)) { return 'loopback-v6' }
    if ($parsed.IsIPv6LinkLocal) { return 'linklocal-v6' }
    if ($parsed.IsIPv6Multicast) { return 'multicast-v6' }
    $bytes = $parsed.GetAddressBytes()
    if (($bytes[0] -band 0xfe) -eq 0xfc) { return 'ula-v6' }
    return 'global-v6'
}

function Get-LabNetworkInventory {
    param([switch]$IncludeSensitive)

    $interfaces = @()
    foreach ($adapter in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        $addresses = @()
        foreach ($unicast in $adapter.GetIPProperties().UnicastAddresses) {
            $addressText = $unicast.Address.ToString()
            $addressItem = [ordered]@{
                family = if ($unicast.Address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
                    'IPv4'
                } else {
                    'IPv6'
                }
                class = Get-LabAddressClass -Address $addressText
            }
            if ($IncludeSensitive) {
                $addressItem.address = $addressText
                $addressItem.prefix_length = $unicast.PrefixLength
            }
            $addresses += [pscustomobject]$addressItem
        }

        $item = [ordered]@{
            interface_id = Get-LabInterfaceId -Id $adapter.Id `
                -Name $adapter.Name -Description $adapter.Description
            type = $adapter.NetworkInterfaceType.ToString()
            status = $adapter.OperationalStatus.ToString()
            speed_bps = [Int64]$adapter.Speed
            addresses = $addresses
        }
        if ($IncludeSensitive) {
            $item.name = $adapter.Name
            $item.description = $adapter.Description
        }
        $interfaces += [pscustomobject]$item
    }
    return $interfaces
}

function Get-LabRouteInventory {
    param([switch]$IncludeSensitive)

    $routes = @()
    try {
        foreach ($line in @(& route.exe print -4 2>$null)) {
            $fields = @($line.Trim() -split '\s+')
            if ($fields.Count -ne 5) { continue }
            $destination = $null
            $netmask = $null
            $gateway = $null
            $interfaceAddress = $null
            $metric = 0
            if (-not [Net.IPAddress]::TryParse($fields[0], [ref]$destination) -or
                -not [Net.IPAddress]::TryParse($fields[1], [ref]$netmask) -or
                -not [Net.IPAddress]::TryParse($fields[2], [ref]$gateway) -or
                -not [Net.IPAddress]::TryParse($fields[3], [ref]$interfaceAddress) -or
                -not [int]::TryParse($fields[4], [ref]$metric)) {
                continue
            }
            $adapter = Get-LabInterfaceForAddress -Address $fields[3]
            $item = [ordered]@{
                family = 'IPv4'
                is_default = $fields[0] -eq '0.0.0.0' -and $fields[1] -eq '0.0.0.0'
                destination_class = if ($fields[0] -eq '0.0.0.0') {
                    'default-or-unspecified-v4'
                } else {
                    Get-LabAddressClass -Address $fields[0]
                }
                gateway_class = Get-LabAddressClass -Address $fields[2]
                interface_address_class = Get-LabAddressClass -Address $fields[3]
                interface_id = if ($null -eq $adapter) {
                    $null
                } else {
                    Get-LabInterfaceId -Id $adapter.id `
                        -Name $adapter.name -Description $adapter.description
                }
                metric = $metric
            }
            if ($IncludeSensitive) {
                $item.destination = $fields[0]
                $item.netmask = $fields[1]
                $item.gateway = $fields[2]
                $item.interface_address = $fields[3]
            }
            $routes += [pscustomobject]$item
        }
    } catch {
        # A missing route.exe is represented by an empty IPv4 route set.
    }

    try {
        foreach ($line in @(& route.exe print -6 2>$null)) {
            if ($line -notmatch '^\s*(\d+)\s+(\d+)\s+(\S+)\s+(.+?)\s*$') { continue }
            $interfaceIndex = [int]$Matches[1]
            $metric = [int]$Matches[2]
            $destinationWithPrefix = $Matches[3]
            $gatewayText = $Matches[4].Trim()
            $destinationText = $destinationWithPrefix.Split('/')[0]
            $destinationAddress = $null
            if (-not [Net.IPAddress]::TryParse($destinationText, [ref]$destinationAddress) -or
                $destinationAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6) {
                continue
            }

            $adapter = $null
            foreach ($candidateAdapter in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
                try {
                    if ($candidateAdapter.GetIPProperties().GetIPv6Properties().Index -eq $interfaceIndex) {
                        $adapter = $candidateAdapter
                        break
                    }
                } catch {
                    continue
                }
            }
            $gatewayAddress = $null
            $gatewayClass = if ([Net.IPAddress]::TryParse($gatewayText.Split('%')[0], [ref]$gatewayAddress)) {
                Get-LabAddressClass -Address $gatewayText
            } else {
                'on-link'
            }
            $item = [ordered]@{
                family = 'IPv6'
                is_default = $destinationWithPrefix -eq '::/0'
                destination_class = if ($destinationWithPrefix -eq '::/0') {
                    'default-v6'
                } else {
                    Get-LabAddressClass -Address $destinationText
                }
                gateway_class = $gatewayClass
                interface_id = if ($null -eq $adapter) {
                    $null
                } else {
                    Get-LabInterfaceId -Id $adapter.Id `
                        -Name $adapter.Name -Description $adapter.Description
                }
                metric = $metric
            }
            if ($IncludeSensitive) {
                $item.destination = $destinationWithPrefix
                $item.gateway = $gatewayText
                $item.interface_index = $interfaceIndex
            }
            $routes += [pscustomobject]$item
        }
    } catch {
        # A missing IPv6 stack or route.exe is represented by an empty IPv6 route set.
    }

    return $routes
}

function Assert-LabApiUrl {
    param(
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [switch]$AllowRemoteApi
    )

    $uri = $null
    if (-not [Uri]::TryCreate($BaseUrl, [UriKind]::Absolute, [ref]$uri)) {
        throw "Invalid API base URL: $BaseUrl"
    }
    if ($uri.Scheme -ne 'http' -and $uri.Scheme -ne 'https') {
        throw "Only HTTP(S) API URLs are supported: $BaseUrl"
    }
    $isLoopback = $uri.IsLoopback -or
        $uri.Host -eq 'localhost' -or
        $uri.Host -eq '127.0.0.1' -or
        $uri.Host -eq '::1'
    if (-not $AllowRemoteApi -and -not $isLoopback) {
        throw 'Remote API access requires -AllowRemoteApi'
    }
    return $uri
}

function Invoke-LabApi {
    param(
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Token = '',
        [switch]$AllowRemoteApi,
        [switch]$AllowUnavailable
    )

    $baseUri = Assert-LabApiUrl -BaseUrl $BaseUrl -AllowRemoteApi:$AllowRemoteApi
    $headers = @{}
    if ($Token) { $headers.Authorization = "Bearer $Token" }
    $requestUri = New-Object Uri($baseUri, $Path)
    try {
        $result = Invoke-RestMethod -Uri $requestUri.AbsoluteUri -Method Get `
            -Headers $headers -TimeoutSec 5
        return [pscustomobject][ordered]@{
            available = $true
            path = $Path
            captured_at_utc = Get-LabUtcTimestamp
            data = $result
            error = $null
        }
    } catch {
        if (-not $AllowUnavailable) { throw }
        return [pscustomobject][ordered]@{
            available = $false
            path = $Path
            captured_at_utc = Get-LabUtcTimestamp
            data = $null
            error = $_.Exception.Message
        }
    }
}

function Get-LabProcessSnapshot {
    param(
        [int[]]$TargetProcessIds = @(),
        [string[]]$ProcessNames = @('emule', 'ese-server', 'ffmpeg')
    )

    $processes = @()
    if ($TargetProcessIds.Count -gt 0) {
        foreach ($targetId in $TargetProcessIds) {
            $process = Get-Process -Id $targetId -ErrorAction SilentlyContinue
            if ($null -ne $process) { $processes += $process }
        }
    } else {
        foreach ($name in $ProcessNames) {
            $processes += @(Get-Process -Name $name -ErrorAction SilentlyContinue)
        }
    }

    $snapshots = @()
    foreach ($process in @($processes | Sort-Object Id -Unique)) {
        $pathName = $null
        try {
            if ($process.Path) { $pathName = Split-Path -Leaf $process.Path }
        } catch {
            $pathName = '<unavailable>'
        }
        $snapshots += [pscustomobject][ordered]@{
            process_id = $process.Id
            process_name = $process.ProcessName
            executable_name = $pathName
            working_set_bytes = [Int64]$process.WorkingSet64
            private_memory_bytes = [Int64]$process.PrivateMemorySize64
            handle_count = $process.HandleCount
            thread_count = @($process.Threads).Count
            cpu_seconds = if ($null -eq $process.CPU) { $null } else { [double]$process.CPU }
            start_time_utc = try {
                $process.StartTime.ToUniversalTime().ToString('o')
            } catch {
                $null
            }
        }
    }
    return $snapshots
}

function Set-LabIniValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value
    )

    $fullPath = Get-LabFullPath -Path $Path
    $null = New-LabDirectory -Path (Split-Path -Parent $fullPath)
    $lines = New-Object 'Collections.Generic.List[string]'
    if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
        foreach ($line in [IO.File]::ReadAllLines($fullPath)) { $null = $lines.Add($line) }
    }

    $sectionPattern = '^\s*\[' + [regex]::Escape($Section) + '\]\s*$'
    $keyPattern = '^\s*' + [regex]::Escape($Key) + '\s*='
    $sectionIndex = -1
    $sectionEnd = $lines.Count
    for ($index = 0; $index -lt $lines.Count; $index++) {
        if ($lines[$index] -match $sectionPattern) {
            $sectionIndex = $index
            for ($next = $index + 1; $next -lt $lines.Count; $next++) {
                if ($lines[$next] -match '^\s*\[.+\]\s*$') {
                    $sectionEnd = $next
                    break
                }
            }
            break
        }
    }

    $newLine = '{0}={1}' -f $Key, $Value
    if ($sectionIndex -ge 0) {
        for ($index = $sectionIndex + 1; $index -lt $sectionEnd; $index++) {
            if ($lines[$index] -match $keyPattern) {
                $lines[$index] = $newLine
                $encoding = New-Object Text.UTF8Encoding($false)
                [IO.File]::WriteAllLines($fullPath, $lines, $encoding)
                return
            }
        }
        $lines.Insert($sectionEnd, $newLine)
    } else {
        if ($lines.Count -gt 0 -and $lines[$lines.Count - 1] -ne '') { $null = $lines.Add('') }
        $null = $lines.Add(('[{0}]' -f $Section))
        $null = $lines.Add($newLine)
    }

    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllLines($fullPath, $lines, $encoding)
}

function Get-LabRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$BasePath,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $baseFullPath = (Get-LabFullPath -Path $BasePath).TrimEnd([char[]]@('\', '/')) + [IO.Path]::DirectorySeparatorChar
    $targetFullPath = Get-LabFullPath -Path $Path
    $baseUri = New-Object Uri($baseFullPath)
    $targetUri = New-Object Uri($targetFullPath)
    $relative = [Uri]::UnescapeDataString($baseUri.MakeRelativeUri($targetUri).ToString())
    return $relative.Replace('/', [IO.Path]::DirectorySeparatorChar)
}

function Split-LabEndpoint {
    param([Parameter(Mandatory = $true)][string]$Endpoint)

    if ($Endpoint -match '^\[(.+)\]:(\d+)$') {
        return [pscustomobject]@{ address = $Matches[1]; port = [int]$Matches[2] }
    }
    if ($Endpoint -match '^(.+):(\d+)$') {
        return [pscustomobject]@{ address = $Matches[1]; port = [int]$Matches[2] }
    }
    throw "Unsupported endpoint: $Endpoint"
}

function Get-LabInterfaceForAddress {
    param([Parameter(Mandatory = $true)][string]$Address)

    $normalized = $Address.Trim('[', ']').Split('%')[0]
    foreach ($adapter in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        foreach ($unicast in $adapter.GetIPProperties().UnicastAddresses) {
            if ($unicast.Address.ToString().Split('%')[0] -eq $normalized) {
                return [pscustomobject][ordered]@{
                    id = $adapter.Id
                    name = $adapter.Name
                    description = $adapter.Description
                    type = $adapter.NetworkInterfaceType.ToString()
                    status = $adapter.OperationalStatus.ToString()
                }
            }
        }
    }
    return $null
}
