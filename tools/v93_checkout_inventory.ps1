param([Parameter(Mandatory=$true)][string]$OutFile,
      [string]$NodeExecutable='node')
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
if(Test-Path -LiteralPath $OutFile) { throw 'Inventory output must be new.' }
function GitLines([string[]]$Arguments) {
    $result=@(& git -C $root -c core.quotepath=false @Arguments)
    if($LASTEXITCODE) { throw 'Git inventory failed.' }
    return $result
}
$base='75c975251d9887aabbc48ed03642c1b286cfd777'
$head=@(GitLines @('rev-parse','HEAD'))[0]
$ancestor=@(GitLines @('merge-base',$base,$head))[0]
$history=GitLines @('diff','--name-status','--no-renames',$base,$head)
$dirty=GitLines @('status','--porcelain','--untracked-files=all')
$paths=@((GitLines @('diff','--name-only','HEAD'))+(GitLines @('ls-files','--others','--exclude-standard')) | Sort-Object -Unique)
$files=@(foreach($path in $paths) {
    $full=Join-Path $root $path
    if(Test-Path -LiteralPath $full -PathType Leaf) {
        [ordered]@{path=$path;sha256=(Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash;review='REQUIRED'}
    } else { [ordered]@{path=$path;missing=$true;review='REQUIRED'} }
})
$unchanged=(@(Compare-Object $dirty (GitLines @('status','--porcelain','--untracked-files=all'))).Count -eq 0)
$msbuild='C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/MSBuild/Current/Bin/MSBuild.exe'
$buildProperties=(& $msbuild (Join-Path $root 'srchybrid/emule.vcxproj') /p:Configuration=Release /p:Platform=x64 '-getProperty:WindowsTargetPlatformVersion,VCToolsVersion,PlatformToolset,WindowsSDK_IncludePath' | Out-String | ConvertFrom-Json).Properties
if($LASTEXITCODE) { throw 'Cannot evaluate build properties.' }
$nodeVersion=(& $NodeExecutable --version | Out-String).Trim()
if($LASTEXITCODE) { throw 'Cannot inspect selected Node executable.' }
$nodePath=(Get-Command $NodeExecutable -ErrorAction Stop).Source
$pythonVersion=(& python --version | Out-String).Trim()
$dependencyFiles=@('third_party/quic/dependencies.lock.json','srchybrid/eSE/package.json','srchybrid/eSE/package-lock.json')
$dependencies=@(foreach($path in $dependencyFiles) {
    [ordered]@{path=$path;sha256=(Get-FileHash -LiteralPath (Join-Path $root $path)).Hash;
        declared_json=(Get-Content -LiteralPath (Join-Path $root $path) -Raw)}
})
$headerVersions=@(foreach($path in @('cryptopp/config_ver.h','zlib/zlib.h','libpng/png.h',
    'mbedtls/include/mbedtls/build_info.h','miniupnpc/include/miniupnpc.h')) {
    $full=Join-Path $root $path
    [ordered]@{path=$path;sha256=(Get-FileHash -LiteralPath $full).Hash;
        declarations=@(Get-Content -LiteralPath $full | Where-Object {
            $_ -match '^\s*#\s*define\s+\w*(VERSION|VER_STRING)\w*\s+'
        });binary_version_attested=$false}
})
[xml]$project=Get-Content -LiteralPath (Join-Path $root 'srchybrid/emule.vcxproj') -Raw
$linkedLibraries=@(foreach($arch in @('Win32','x64')) {
    $zlibDirectory=(& $msbuild (Join-Path $root 'srchybrid/emule.vcxproj') /p:Configuration=Release "/p:Platform=$arch" -getProperty:ZlibPlatform | Out-String).Trim()
    if($LASTEXITCODE -or !$zlibDirectory) { throw 'Cannot evaluate ZlibPlatform.' }
    $group=$project.Project.ItemDefinitionGroup | Where-Object {
        $_.Condition -eq "'`$(Configuration)|`$(Platform)'=='Release|$arch'"
    }
    foreach($declared in ([string]$group.Link.AdditionalDependencies).Split(';')) {
        if(!$declared -or $declared -eq '%(AdditionalDependencies)') { continue }
        $resolved=$declared.Replace('$(Platform)',$arch).Replace('$(Configuration)','Release').Replace('$(ZlibPlatform)',$zlibDirectory)
        if($resolved.Contains('\') -or $resolved.Contains('/')) {
            $full=[IO.Path]::GetFullPath((Join-Path (Join-Path $root 'srchybrid') $resolved))
            $exists=Test-Path -LiteralPath $full -PathType Leaf
            [ordered]@{architecture=$arch;declared=$declared;path=$full;exists=$exists;
                sha256=$(if($exists) { (Get-FileHash -LiteralPath $full).Hash } else { $null });
                binary_version_attested=$false}
        } else {
            [ordered]@{architecture=$arch;declared=$declared;resolution='MSVC/Windows SDK library search path'}
        }
    }
})
$manifest=[ordered]@{schema='ese.v93.checkout-inventory/1';generated_utc=[DateTime]::UtcNow.ToString('o');
    root=$root;selected_development_head=$head;planned_rc2=$base;merge_base=$ancestor;
    planned_rc2_is_selected_head_ancestor=($ancestor -eq $base);
    history_delta=$history;checkout_status=$dirty;local_files=$files;status_unchanged_during_scan=$unchanged;
    compiler=[ordered]@{msbuild_version=(Get-Item -LiteralPath $msbuild).VersionInfo.FileVersion;properties=$buildProperties};
    runtimes=[ordered]@{node=$nodeVersion;node_executable=$nodePath;expected_node_major=22;node_requirement_met=($nodeVersion -match '^v22\.');python=$pythonVersion};
    submodules=(GitLines @('submodule','status'));dependency_manifests=$dependencies;dependency_header_versions=$headerVersions;
    linked_libraries=$linkedLibraries;
    reconciliation_complete=$false;functional_cards_closed=0}
[IO.File]::WriteAllText([IO.Path]::GetFullPath($OutFile),($manifest|ConvertTo-Json -Depth 20),[Text.Encoding]::UTF8)
Write-Output "Inventory: history=$($history.Count), local=$($files.Count), stable-status=$unchanged; reconciliation remains open."
if(!$unchanged) { exit 1 }
