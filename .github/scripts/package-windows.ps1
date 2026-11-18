# Build the Windows installer: stage the programs, the app bundle and the
# documents, then compile windows/deepwork.iss with Inno Setup (installed
# here if missing, from a pinned download).
param(
    [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string]$Arch,
    # Folder with deepwork-daemon.exe and deepworkctl.exe.
    [Parameter(Mandatory)][string]$Bin,
    # The app bundle (bundle-windows-app.sh).
    [Parameter(Mandatory)][string]$App,
    [string]$Out = 'dist'
)
$ErrorActionPreference = 'Stop'

$InnoVersion = '6.7.4'
$InnoSha256 = 'a549929319f9120716677c685535ca4671e4b937b5fdc87e2585f32d8eb30e8c'
$RceditVersion = 'v2.0.0'
$RceditSha256 = '3e7801db1a5edbec91b49a24a094aad776cb4515488ea5a4ca2289c400eade2a'

function Download([string]$url, [string]$file, [string]$sha256) {
    if (-not (Test-Path $file)) { Invoke-WebRequest $url -OutFile $file }
    $hash = (Get-FileHash $file -Algorithm SHA256).Hash
    if ($hash -ne $sha256) { throw "$url has the wrong checksum: $hash" }
}

$version = (Select-String -Path Cargo.toml -Pattern '^version = "(.*)"' | Select-Object -First 1).Matches[0].Groups[1].Value

$iscc = @(
    (Join-Path $env:RUNNER_TEMP 'inno\ISCC.exe'),
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $iscc) {
    $setup = Join-Path $env:RUNNER_TEMP "innosetup-$InnoVersion.exe"
    $tag = 'is-' + $InnoVersion.Replace('.', '_')
    Download "https://github.com/jrsoftware/issrc/releases/download/$tag/innosetup-$InnoVersion.exe" $setup $InnoSha256
    $dir = Join-Path $env:RUNNER_TEMP 'inno'
    $p = Start-Process $setup -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', "/DIR=$dir" -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "Installing Inno Setup failed ($($p.ExitCode))" }
    $iscc = Join-Path $dir 'ISCC.exe'
}

$stage = Join-Path $env:RUNNER_TEMP "deepwork-stage-$Arch"
Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory $stage | Out-Null
Copy-Item "$App/*" $stage -Recurse
Copy-Item "$Bin/deepwork-daemon.exe", "$Bin/deepworkctl.exe", README.md, LICENSE $stage
# Version information, icon and manifest in every program (file properties,
# Task Manager, SmartScreen).
$rcedit = Join-Path $env:RUNNER_TEMP 'rcedit-x64.exe'
Download "https://github.com/electron/rcedit/releases/download/$RceditVersion/rcedit-x64.exe" $rcedit $RceditSha256
$programs = @(
    @{ File = 'deepwork.exe'; Description = 'DeepWork'; Manifest = 'windows\app.manifest' },
    @{ File = 'deepwork-daemon.exe'; Description = 'DeepWork service'; Manifest = 'windows\tools.manifest' },
    @{ File = 'deepworkctl.exe'; Description = 'DeepWork command line'; Manifest = 'windows\tools.manifest' }
)
foreach ($p in $programs) {
    & $rcedit (Join-Path $stage $p.File) `
        --set-version-string FileDescription $p.Description `
        --set-version-string ProductName DeepWork `
        --set-version-string CompanyName 'DeepWork contributors' `
        --set-version-string LegalCopyright 'GPL-3.0-or-later' `
        --set-version-string OriginalFilename $p.File `
        --set-file-version $version --set-product-version $version `
        --set-icon windows\deepwork.ico --application-manifest $p.Manifest
    if ($LASTEXITCODE -ne 0) { throw "rcedit failed on $($p.File)" }
}

# Licenses of the Rust crates (the MSYS2 ones came with the app bundle).
python .github/scripts/third_party_notices.py (Join-Path $stage 'THIRD-PARTY-NOTICES.txt')
if ($LASTEXITCODE -ne 0) { throw 'third_party_notices.py failed' }

New-Item -ItemType Directory -Force $Out | Out-Null
$outDir = (Resolve-Path $Out).Path
& $iscc /Q "/DVersion=$version" "/DArch=$Arch" "/DSource=$stage" "/DOutput=$outDir" windows\deepwork.iss
if ($LASTEXITCODE -ne 0) { throw "ISCC failed ($LASTEXITCODE)" }

# Debug information, published next to the installer: PDBs of the service
# and command line, and the app's DWARF file.
$symbols = Join-Path $env:RUNNER_TEMP "deepwork-$version-windows-$Arch-symbols"
Remove-Item -Recurse -Force $symbols -ErrorAction SilentlyContinue
New-Item -ItemType Directory $symbols | Out-Null
Get-ChildItem "$Bin/*.pdb" -ErrorAction SilentlyContinue | Copy-Item -Destination $symbols
if (Test-Path "$App-symbols") { Copy-Item "$App-symbols/*" $symbols }
Compress-Archive -Path "$symbols/*" -DestinationPath (Join-Path $outDir "deepwork-$version-windows-$Arch-symbols.zip") -Force
Get-ChildItem $outDir
