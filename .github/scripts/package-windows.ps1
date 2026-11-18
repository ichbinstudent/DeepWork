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

$version = (Select-String -Path Cargo.toml -Pattern '^version = "(.*)"' | Select-Object -First 1).Matches[0].Groups[1].Value

$iscc = @(
    (Join-Path $env:RUNNER_TEMP 'inno\ISCC.exe'),
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $iscc) {
    $setup = Join-Path $env:RUNNER_TEMP "innosetup-$InnoVersion.exe"
    $tag = 'is-' + $InnoVersion.Replace('.', '_')
    Invoke-WebRequest "https://github.com/jrsoftware/issrc/releases/download/$tag/innosetup-$InnoVersion.exe" -OutFile $setup
    $hash = (Get-FileHash $setup -Algorithm SHA256).Hash
    if ($hash -ne $InnoSha256) { throw "Inno Setup download has the wrong checksum: $hash" }
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
if (Test-Path THIRD-PARTY-NOTICES.txt) { Copy-Item THIRD-PARTY-NOTICES.txt $stage }
if (Test-Path "$App/third-party") { Copy-Item "$App/third-party" $stage -Recurse -Force }

New-Item -ItemType Directory -Force $Out | Out-Null
$outDir = (Resolve-Path $Out).Path
& $iscc /Q "/DVersion=$version" "/DArch=$Arch" "/DSource=$stage" "/DOutput=$outDir" windows\deepwork.iss
if ($LASTEXITCODE -ne 0) { throw "ISCC failed ($LASTEXITCODE)" }
Get-ChildItem $outDir
