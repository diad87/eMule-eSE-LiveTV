$ErrorActionPreference='Stop'
$root='C:\tmp\v93-a2-classic-vm01'
$manifest=Get-Content -LiteralPath (Join-Path $root 'provisioning.json') -Raw | ConvertFrom-Json
if($manifest.schema -ne 'ese.v93.classic-hyperv-lab/1' -or $manifest.root -ne $root -or
    $manifest.vm_name -ne 'eSE-A2-Classic-Isolated-01') { throw 'Unexpected lab manifest.' }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(!([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run elevated; no host account/group modifications are performed.'
}
Import-Module Hyper-V
$vm=Get-VM -Id ([guid]$manifest.vm_id)
if($vm.Name -ne $manifest.vm_name) { throw 'VM identity mismatch.' }
$adapters=@(Get-VMNetworkAdapter -VM $vm)
if($adapters.Count -ne 1 -or [string]$adapters[0].SwitchId -ne $manifest.switch_id) { throw 'Unexpected VM network.' }
$switch=Get-VMSwitch -Id ([guid]$manifest.switch_id)
if($switch.SwitchType -ne 'Private') { throw 'Private isolation required.' }
$disks=@(Get-VMHardDiskDrive -VM $vm)
if($disks.Count -ne 1 -or $disks[0].Path -ne (Join-Path $root 'classic-os.vhdx')) { throw 'Unexpected VM disk.' }
$dvd=@(Get-VMDvdDrive -VM $vm)
if($dvd.Count -ne 1 -or $dvd[0].Path -ne $manifest.iso_path) { throw 'Unexpected installation media.' }
if((Get-PSDrive C).Free -lt 45GB) { throw 'Need45GiB free before installation; no cleanup will be performed.' }
if($vm.State -eq 'Off') { Start-VM -VM $vm }
elseif($vm.State -ne 'Running') { throw 'Unexpected VM state; do not force it.' }
$state=[ordered]@{schema='ese.v93.classic-vm-install/1';checked_utc=[DateTime]::UtcNow.ToString('o');
    vm_id=$manifest.vm_id;switch_type='Private';phase='CONSOLE_OPENED_INSTALLATION_PENDING';
    os_installed=$false;classic_acceptance='NOT_RUN'}
[IO.File]::WriteAllText((Join-Path $root 'installation-start.json'),($state|ConvertTo-Json),[Text.Encoding]::UTF8)
# Visible console is intentional: the user needs to install Windows and handle
# its license/account choices inside the guest. Basic session, no /edit redirects.
Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\vmconnect.exe') `
    -ArgumentList @('localhost',$manifest.vm_name)
Write-Output 'Owned isolated VM console opened. Windows installation and acceptance tests remain pending.'
