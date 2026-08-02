[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$JobRequestPath
)

$ErrorActionPreference = 'Stop'

function Invoke-AuditProbe {
    param([Parameter(Mandatory = $true)][scriptblock]$Script)

    try {
        [pscustomobject]@{
            ok = $true
            value = & $Script
            error = $null
        }
    } catch {
        [pscustomobject]@{
            ok = $false
            value = $null
            error = $_.Exception.Message
        }
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdmin = $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

$hyperV = Invoke-AuditProbe {
    $command = Get-Command Get-VM -ErrorAction Stop
    $vms = @(Get-VM -ErrorAction Stop | ForEach-Object {
        [ordered]@{
            name = $_.Name
            state = [string]$_.State
            generation = [int]$_.Generation
            path = $_.Path
            configuration_location = $_.ConfigurationLocation
        }
    })
    $switches = @(Get-VMSwitch -ErrorAction Stop | ForEach-Object {
        [ordered]@{
            name = $_.Name
            type = [string]$_.SwitchType
            adapter = $_.NetAdapterInterfaceDescription
        }
    })
    [ordered]@{
        module = $command.Source
        vms = $vms
        switches = $switches
    }
}

$optionalFeatures = Invoke-AuditProbe {
    @(
        'Microsoft-Hyper-V-All',
        'Containers-DisposableClientVM',
        'Containers'
    ) | ForEach-Object {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $_ `
            -ErrorAction SilentlyContinue
        [ordered]@{
            name = $_
            state = if ($null -eq $feature) {
                'ABSENT'
            } else {
                [string]$feature.State
            }
        }
    }
}

$candidateDisks = Invoke-AuditProbe {
    $roots = @(
        'C:\ProgramData\Microsoft\Windows\Virtual Hard Disks',
        'C:\Users\Public\Documents\Hyper-V\Virtual hard disks',
        'C:\VM',
        'D:\VM'
    )
    @($roots | Where-Object { Test-Path -LiteralPath $_ } |
        ForEach-Object {
            Get-ChildItem -LiteralPath $_ -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object Extension -In @('.vhd', '.vhdx') |
                Select-Object -First 20 |
                ForEach-Object {
                    [ordered]@{
                        path = $_.FullName
                        bytes = [Int64]$_.Length
                    }
                }
        })
}

$physical = Invoke-AuditProbe {
    @(Get-NetAdapter -Physical -ErrorAction Stop | ForEach-Object {
        $adapter = $_
        [ordered]@{
            name = $adapter.Name
            if_index = [int]$adapter.ifIndex
            status = [string]$adapter.Status
            description = $adapter.InterfaceDescription
            addresses = @(
                Get-NetIPAddress -InterfaceIndex $adapter.ifIndex `
                    -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        [ordered]@{
                            family = [string]$_.AddressFamily
                            address = $_.IPAddress
                            prefix_length = [int]$_.PrefixLength
                            state = [string]$_.AddressState
                        }
                    }
            )
        }
    })
}

$result = [ordered]@{
    schema = 'ese.v91.t5-capability-audit/v1'
    status = 'AUDIT_COMPLETE'
    created_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    computer = $env:COMPUTERNAME
    identity = $identity.Name
    elevated = $isAdmin
    os = [ordered]@{
        caption = (Get-CimInstance Win32_OperatingSystem).Caption
        version = [Environment]::OSVersion.Version.ToString()
        build = [Environment]::OSVersion.Version.Build
    }
    hyper_v = $hyperV
    optional_features = $optionalFeatures
    candidate_disks = $candidateDisks
    physical_adapters = $physical
}

$result | ConvertTo-Json -Depth 10
