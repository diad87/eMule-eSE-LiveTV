param(
    [Parameter(Mandatory=$true)][string]$WorkRoot,
    [string]$CacheRoot,
    [string]$GpgDirectory = "$env:ProgramFiles/Git/usr/bin",
    [switch]$Offline
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path $PSScriptRoot -Parent
$candidatePath = Join-Path $repo 'third_party/quic/msys2-gnutls-x64-candidate.json'
$lockPath = Join-Path $repo 'third_party/quic/dependencies.lock.json'
$candidate = Get-Content -LiteralPath $candidatePath -Raw | ConvertFrom-Json
$lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
$work = [IO.Path]::GetFullPath($WorkRoot)
if (Test-Path -LiteralPath $work) { throw 'A fresh candidate work directory is required.' }
$null = New-Item -Path $work -ItemType Directory
if (!$CacheRoot) { $CacheRoot = Join-Path $work 'archives' }
$cache = [IO.Path]::GetFullPath($CacheRoot)
$null = New-Item -Path $cache -ItemType Directory -Force
$runtime = Join-Path $work 'runtime-x64'
$notices = Join-Path $work 'notices-x64'
$sources = Join-Path $work 'sources-x64'
$probeRuntime = Join-Path $work 'probe-runtime'
$keyHome = Join-Path $work 'keyring'
$null = New-Item -Path $runtime,$notices,$sources,$probeRuntime,$keyHome -ItemType Directory
$gpg = Join-Path $GpgDirectory 'gpg.exe'
$gpgv = Join-Path $GpgDirectory 'gpgv.exe'

function Assert-Hash([string]$Path,[string]$Expected) {
    if ((Get-FileHash -LiteralPath $Path).Hash -ne $Expected) { throw "SHA-256 mismatch: $Path" }
}

function Get-PinnedFile([string]$Url,[string]$Name,[string]$Hash) {
    if ($Name -ne [IO.Path]::GetFileName($Name)) { throw "Invalid archive name: $Name" }
    $destination = Join-Path $cache $Name
    if (!(Test-Path -LiteralPath $destination)) {
        if ($Offline) { throw "Offline input missing: $destination" }
        $temporary = "$destination.$([Guid]::NewGuid().ToString('N')).tmp"
        try {
            & curl.exe -fsSL --retry 2 -o $temporary $Url
            if ($LASTEXITCODE) { throw "Download failed: $Url" }
            Assert-Hash $temporary $Hash
            Move-Item -LiteralPath $temporary -Destination $destination
        } finally {
            if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
        }
    }
    Assert-Hash $destination $Hash
    return $destination
}

function Invoke-Checked([string]$Exe,[string[]]$Arguments,[string]$LogName) {
    $log = Join-Path $work "$LogName.log"
    $ErrorActionPreference = 'Continue'
    & $Exe @Arguments 2>&1 | ForEach-Object { "$_" } | Set-Content -LiteralPath $log -Encoding utf8
    if ($LASTEXITCODE) { throw "$LogName failed with exit $LASTEXITCODE. See $log" }
}

function Assert-Signature([string]$Archive,[string]$Signature,[string]$Keyring,[string]$SigningKey,[string]$PrimaryKey) {
    $name = [IO.Path]::GetFileName($Archive)
    Invoke-Checked $gpgv @('--homedir',$keyHome,'--keyring',$Keyring,'--status-fd','1',$Signature,$Archive) "$name.verify"
    $statuses = @(Get-Content -LiteralPath (Join-Path $work "$name.verify.log") | Where-Object { $_.StartsWith('[GNUPG:] VALIDSIG ') })
    if ($statuses.Count -ne 1) { throw "Expected one valid signature for $name" }
    $fields = $statuses[0] -split ' +'
    if ($fields[2] -ne $SigningKey -or $fields[-1] -ne $PrimaryKey) { throw "Unexpected signer for $name" }
}

$msysKey = Get-PinnedFile $candidate.keyring_url 'msys2.gpg' $candidate.keyring_sha256
$ngtcp2Key = Get-PinnedFile $candidate.ngtcp2.key_url 'tatsuhiro-t.gpg' $candidate.ngtcp2.key_sha256
Invoke-Checked $gpg @('--batch','--output',(Join-Path $keyHome 'msys2.gpg'),'--dearmor',$msysKey) 'msys2-keyring'
Invoke-Checked $gpg @('--batch','--output',(Join-Path $keyHome 'ngtcp2.gpg'),'--dearmor',$ngtcp2Key) 'ngtcp2-keyring'
$ngtcp2Name = "ngtcp2-$($lock.ngtcp2.version).tar.gz"
$ngtcp2Archive = Get-PinnedFile $lock.ngtcp2.url $ngtcp2Name $lock.ngtcp2.sha256
$ngtcp2Signature = Get-PinnedFile $lock.ngtcp2.signature_url "$ngtcp2Name.asc" $candidate.ngtcp2.signature_sha256
Assert-Signature $ngtcp2Archive $ngtcp2Signature 'ngtcp2.gpg' $candidate.ngtcp2.signer_fingerprint $candidate.ngtcp2.primary_fingerprint
Invoke-Checked 'tar.exe' @('-xf',$ngtcp2Archive,'-C',$work) 'ngtcp2-extract'
Copy-Item -LiteralPath $ngtcp2Archive,$ngtcp2Signature -Destination $sources
$ngtcp2Notices = New-Item -Path (Join-Path $notices 'ngtcp2') -ItemType Directory
Copy-Item -LiteralPath (Join-Path $work "ngtcp2-$($lock.ngtcp2.version)/COPYING") -Destination $ngtcp2Notices.FullName
Copy-Item -LiteralPath (Join-Path $repo 'third_party/quic/DISTRIBUTION.md') -Destination $notices

foreach ($entry in $candidate.packages) {
    $name = $entry.package
    $signatureName = "$name$($candidate.signature_suffix)"
    $archive = Get-PinnedFile "$($candidate.binary_base_url)$name" $name $entry.sha256
    $signature = Get-PinnedFile "$($candidate.binary_base_url)$signatureName" $signatureName $entry.signature_sha256
    Assert-Signature $archive $signature 'msys2.gpg' $candidate.package_signer_fingerprint $candidate.package_signer_fingerprint
    $sourceName = $entry.source
    $sourceSignatureName = "$sourceName$($candidate.signature_suffix)"
    $sourceArchive = Get-PinnedFile "$($candidate.source_base_url)$sourceName" $sourceName $entry.source_sha256
    $sourceSignature = Get-PinnedFile "$($candidate.source_base_url)$sourceSignatureName" $sourceSignatureName $entry.source_signature_sha256
    Assert-Signature $sourceArchive $sourceSignature 'msys2.gpg' $candidate.package_signer_fingerprint $candidate.package_signer_fingerprint
    Copy-Item -LiteralPath $sourceArchive,$sourceSignature -Destination $sources
    Invoke-Checked 'tar.exe' @('-xOf',$archive,'.BUILDINFO') "$name.metadata"
    $expectedRecipe = "pkgbuild_sha256sum = $($entry.recipe_sha256)"
    if ($expectedRecipe -notin (Get-Content -LiteralPath (Join-Path $work "$name.metadata.log"))) {
        throw "Source recipe differs from signed build metadata: $name"
    }
    Invoke-Checked 'tar.exe' @('-xf',$sourceArchive,'-C',$work,$entry.recipe_path) "$sourceName.recipe"
    Assert-Hash (Join-Path $work $entry.recipe_path) $entry.recipe_sha256
    $members = foreach ($dll in $entry.dlls.PSObject.Properties) { "mingw64/bin/$($dll.Name)" }
    $members = @($members) + @($entry.binary_license_files)
    if ($entry.dlls.PSObject.Properties.Name -contains 'libgnutls-30.dll') {
        $members += @('mingw64/include/gnutls','mingw64/lib/libgnutls.dll.a')
    }
    Invoke-Checked 'tar.exe' (@('-xf',$archive,'-C',$work) + $members) "$name.extract"
    foreach ($notice in $entry.binary_license_files) {
        $relativeNotice = $notice.Substring('mingw64/share/licenses/'.Length)
        $noticePath = Join-Path $notices $relativeNotice
        $null = New-Item -Path (Split-Path $noticePath) -ItemType Directory -Force
        Copy-Item -LiteralPath (Join-Path $work $notice) -Destination $noticePath
    }
    if (!$entry.binary_license_files.Count) {
        Invoke-Checked 'tar.exe' @('-xf',$sourceArchive,'-C',$work,$entry.source_license_archive) "$sourceName.upstream"
        $upstream = Join-Path $work $entry.source_license_archive
        Invoke-Checked 'tar.exe' (@('-xf',$upstream,'-C',$notices) + @($entry.source_license_files)) "$sourceName.notices"
    }
    foreach ($dll in $entry.dlls.PSObject.Properties) {
        $dllPath = Join-Path $work "mingw64/bin/$($dll.Name)"
        Assert-Hash $dllPath $dll.Value.sha256
        Copy-Item -LiteralPath $dllPath -Destination $runtime
    }
}

$vswhere = "${env:ProgramFiles(x86)}/Microsoft Visual Studio/Installer/vswhere.exe"
$vsRoot = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -or !$vsRoot) { throw 'Visual Studio with MSVC tools is required.' }
$cmake = Join-Path $vsRoot 'Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe'
if ((& $cmake --version | Select-Object -First 1) -ne "cmake version $($lock.toolchain.cmake_version)") {
    throw 'CMake version differs from the dependency lock.'
}
$ngtcp2 = Join-Path $work "ngtcp2-$($lock.ngtcp2.version)"
$build = Join-Path $work 'build-x64'
$probe = Join-Path $work 'probe'
$include = Join-Path $work 'include-x64'
Move-Item -LiteralPath (Join-Path $work 'mingw64/include') -Destination $include
$import = Join-Path $work 'gnutls-x64.lib'
Move-Item -LiteralPath (Join-Path $work 'mingw64/lib/libgnutls.dll.a') -Destination $import
Assert-Hash $import $candidate.gnutls_import_sha256
$compiler = @('-G',$lock.toolchain.generator,'-A','x64',
    '-T',"$($lock.toolchain.toolset),version=$($lock.toolchain.msvc_tools_version)",
    "-DCMAKE_SYSTEM_VERSION=$($lock.toolchain.windows_sdk)",'-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded')
$flags = foreach ($property in $lock.flags.PSObject.Properties) { "-D$($property.Name)=$($property.Value)" }
Invoke-Checked $cmake (@('-S',$ngtcp2,'-B',$build) + $compiler + $flags + @(
    "-DGNUTLS_INCLUDE_DIR=$include","-DGNUTLS_LIBRARY=$import")) 'ngtcp2-configure'
Invoke-Checked $cmake @('--build',$build,'--config','Release','--target','ngtcp2','ngtcp2_crypto_gnutls','--parallel','3') 'ngtcp2-build'
Invoke-Checked $cmake (@('-S',(Join-Path $PSScriptRoot 'quic'),'-B',$probe) + $compiler + @(
    "-DNGTCP2_SOURCE=$ngtcp2","-DNGTCP2_BUILD=$build","-DGNUTLS_INCLUDE=$include","-DGNUTLS_IMPORT=$import")) 'probe-configure'
Invoke-Checked $cmake @('--build',$probe,'--config','Release','--target','quic_dependency_smoke','quic_loopback','native_quic_loopback','--parallel','3') 'probe-build'
Copy-Item -LiteralPath (Join-Path $build 'lib/Release/ngtcp2.dll'),(Join-Path $build 'crypto/gnutls/Release/ngtcp2_crypto_gnutls.dll') -Destination $runtime
Copy-Item -LiteralPath @(Get-ChildItem -LiteralPath $runtime -File | Select-Object -ExpandProperty FullName) -Destination $probeRuntime
foreach ($name in @('quic_dependency_smoke','quic_loopback','native_quic_loopback')) {
    Copy-Item -LiteralPath (Join-Path $probe "Release/$name.exe") -Destination $probeRuntime
}
Invoke-Checked (Join-Path $probeRuntime 'quic_dependency_smoke.exe') @() 'abi'
Invoke-Checked (Join-Path $probeRuntime 'quic_loopback.exe') @() 'loopback-clean'
foreach ($test in @('wrong-alpn','bad-auth','loss')) {
    Invoke-Checked (Join-Path $probeRuntime 'quic_loopback.exe') @("--$test") "loopback-$test"
}
foreach ($test in @('clean','loss','bad-auth','dco')) {
    Invoke-Checked (Join-Path $probeRuntime 'native_quic_loopback.exe') @($test) "native-$test"
}

function Get-Records([System.IO.FileInfo[]]$Files) {
    foreach ($file in ($Files | Sort-Object FullName)) {
        [ordered]@{
            path=$file.FullName.Substring($work.TrimEnd('\','/').Length+1).Replace('\','/')
            sha256=(Get-FileHash -LiteralPath $file.FullName).Hash
            size=$file.Length
        }
    }
}

$dumpbin = Join-Path $vsRoot "VC/Tools/MSVC/$($lock.toolchain.msvc_tools_version)/bin/Hostx64/x64/dumpbin.exe"
$runtimeFiles = @(Get-ChildItem -LiteralPath $runtime -File -Filter '*.dll')
$pinnedImports = @{}
foreach ($entry in $candidate.packages) {
    foreach ($dll in $entry.dlls.PSObject.Properties) { $pinnedImports.Add($dll.Name, @($dll.Value.imports)) }
}
$windowsImports = @('advapi32.dll','bcrypt.dll','crypt32.dll','kernel32.dll','msvcrt.dll','ncrypt.dll','shell32.dll','ws2_32.dll')
$imports = [ordered]@{}
foreach ($file in ($runtimeFiles | Sort-Object Name)) {
    Invoke-Checked $dumpbin @('/nologo','/dependents',$file.FullName) "$($file.Name).imports"
    $dependencies = @(Get-Content -LiteralPath (Join-Path $work "$($file.Name).imports.log") |
        ForEach-Object { if ($_ -match '^\s+([A-Za-z0-9._-]+\.dll)\s*$') { $Matches[1].ToLowerInvariant() } } |
        Sort-Object -Unique)
    if (!$dependencies.Count) { throw "No imports found for $($file.Name)" }
    foreach ($dependency in $dependencies) {
        if ($dependency -notin $runtimeFiles.Name -and $dependency -notin $windowsImports) {
            throw "Unresolved runtime dependency $dependency from $($file.Name)"
        }
    }
    if ($pinnedImports.ContainsKey($file.Name) -and
        (Compare-Object ($pinnedImports[$file.Name] | Sort-Object) $dependencies)) {
        throw "Imports do not match the pinned inventory for $($file.Name)"
    }
    $imports.Add($file.Name, $dependencies)
}

$headerRoots = @((Join-Path $ngtcp2 'lib/includes'),(Join-Path $ngtcp2 'crypto/includes'),
    (Join-Path $build 'lib/includes'),$include)
$headers = @(Get-ChildItem -LiteralPath $headerRoots -Recurse -File -Filter '*.h')
$links = @(Get-Item -LiteralPath $import,(Join-Path $build 'lib/Release/ngtcp2.lib'),
    (Join-Path $build 'crypto/gnutls/Release/ngtcp2_crypto_gnutls.lib'))
[ordered]@{
    schema='ese.quic.release-dependencies/v1'
    architecture='x64'
    scope='Signed MSYS2 inputs, rebuilt ngtcp2, ABI and standalone UDP loopback'
    lock_sha256=(Get-FileHash -LiteralPath $lockPath).Hash
    msys2_candidate_sha256=(Get-FileHash -LiteralPath $candidatePath).Hash
    workflow_sha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash
    runtime=@(Get-Records $runtimeFiles)
    runtime_imports=$imports
    dependency_headers=@(Get-Records $headers)
    link_inputs=@(Get-Records $links)
    notices=@(Get-Records @(Get-ChildItem -LiteralPath $notices -Recurse -File))
    sources=@(Get-Records @(Get-ChildItem -LiteralPath $sources -File))
    tests=@('abi','loopback-clean','loopback-wrong-alpn','loopback-bad-auth','loopback-loss',
        'native-clean','native-loss','native-bad-auth','native-dco')
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $work 'manifest-x64.json') -Encoding utf8
& (Join-Path $PSScriptRoot 'verify_quic_release_dependencies.ps1') -Root $work
Write-Host "Signed x64 QUIC dependencies passed ABI and eight UDP loopback cases. Manifest in $work"
