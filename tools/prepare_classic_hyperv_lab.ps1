param(
    [string]$Root='C:\tmp\v93-a2-classic-vm01',
    [string]$WindowsIso='C:\tmp\Win11_25H2_Spanish_x64_v2.iso'
)
$ErrorActionPreference='Stop'
$target=[IO.Path]::GetFullPath($Root)
if($target -ne 'C:\tmp\v93-a2-classic-vm01') { throw 'Only the explicitly owned lab directory is supported.' }
if(Test-Path -LiteralPath $target) { throw 'Lab directory must be new; no overwrite or reuse.' }
$ancestor=Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($target))
while($ancestor) {
    if($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse ancestor.' }
    $ancestor=$ancestor.Parent
}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(!([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this provisioning script elevated; no host account/group changes are performed.'
}
Import-Module Hyper-V -ErrorAction Stop
$iso=Get-Item -LiteralPath $WindowsIso
if($iso.PSIsContainer -or $iso.Extension -ne '.iso' -or ($iso.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Expected regular ISO.' }
if((Get-PSDrive C).Free -lt 45GB) { throw 'At least45 GiB free required before provisioning. No space cleanup is performed.' }
$vmName='eSE-A2-Classic-Isolated-01'
$switchName='eSE-A2-Private-01'
if(Get-VM -Name $vmName -ErrorAction SilentlyContinue) { throw 'VM name already exists; never modify it.' }
if(Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue) { throw 'Switch name already exists; never reuse it.' }
$null=New-Item -ItemType Directory -Path $target
$status=[ordered]@{schema='ese.v93.classic-hyperv-lab/1';status='CREATING';created_utc=[DateTime]::UtcNow.ToString('o');
    vm_name=$vmName;switch_name=$switchName;root=$target;iso_path=$iso.FullName;
    os_installed=$false;clients_launched=$false;classic_acceptance='NOT_RUN';
    isolation='Private switch, no host vNIC, no physical uplink/NAT, no host folder sharing; VM initially off';
    disk='64GiB dynamic; monitor host storage before installation; retain at least20GiB free'}
$report=Join-Path $target 'provisioning.json'
function Save-Status { [IO.File]::WriteAllText($report,($status|ConvertTo-Json -Depth 6),[Text.Encoding]::UTF8) }
try {
    Save-Status
    $switch=New-VMSwitch -Name $switchName -SwitchType Private
    $status.switch_id=[string]$switch.Id; Save-Status
    $vm=New-VM -Name $vmName -Generation 2 -MemoryStartupBytes 4GB -Path $target `
        -NewVHDPath (Join-Path $target 'classic-os.vhdx') -NewVHDSizeBytes 64GB -SwitchName $switchName
    $status.vm_id=[string]$vm.Id; Save-Status
    Set-VM -VM $vm -ProcessorCount 2 -AutomaticStartAction Nothing -AutomaticStopAction ShutDown -CheckpointType Standard
    Set-VMMemory -VM $vm -DynamicMemoryEnabled $false
    Set-VMKeyProtector -VM $vm -NewLocalKeyProtector
    Enable-VMTPM -VM $vm
    $dvd=Add-VMDvdDrive -VM $vm -Path $iso.FullName -Passthru
    Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows -FirstBootDevice $dvd
    # Guest file-copy service stays disabled. No host shares, clipboard/redirection
    # configuration, host registry edits, user creation, firewall or group changes.
    $copyService=Get-VMIntegrationService -VM $vm | Where-Object { [string]$_.Id -eq '6C09BB55-D683-4DA0-8931-C9BF705F6480' }
    if($copyService) { $copyService | Disable-VMIntegrationService }
    $adapter=Get-VMNetworkAdapter -VM $vm
    $actualSwitch=Get-VMSwitch -Id $adapter.SwitchId
    if($actualSwitch.SwitchType -ne 'Private' -or $vm.State -ne 'Off') { throw 'Isolation invariant failed.' }
    $status.status='VM_CREATED_OFF_OS_NOT_INSTALLED'; Save-Status
} catch {
    $status.status='FAILED_RETAINED';$status.error=$_.Exception.Message;Save-Status
    # Keep exact owned resources for inspection; no recursive deletion/rollback.
    throw
}
