# End-to-end test of the Windows installer on a CI runner (runs as
# administrator): install, block a site, check the hosts file, Chrome's policy
# and the app, crash the service, update with a locked block, try to
# uninstall and downgrade, uninstall, and check that nothing is left behind.
param(
    # The installer to test (package-windows.ps1).
    [Parameter(Mandatory)][string]$Setup
)
$ErrorActionPreference = 'Stop'

$dir = Join-Path $env:ProgramFiles 'DeepWork'
$data = Join-Path $env:ProgramData 'DeepWork'
$ctl = Join-Path $dir 'deepworkctl.exe'
$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$chrome = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
$chromeBefore = Test-Path $chrome
$programs = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
$uninstallKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{6F0E5B2A-6A8B-4D7E-9C59-2E3D1C4B7A10}_is1'
$logs = Join-Path $env:RUNNER_TEMP 'shots'
New-Item -ItemType Directory -Force $logs | Out-Null
$version = (Select-String -Path Cargo.toml -Pattern '^version = "(.*)"' | Select-Object -First 1).Matches[0].Groups[1].Value

function Check([bool]$ok, [string]$what) {
    if (-not $ok) {
        Write-Host "FAILED: $what" -ForegroundColor Red
        if (Test-Path "$data\deepwork.log") { Get-Content "$data\deepwork.log" }
        exit 1
    }
    Write-Host "ok: $what"
}
function Save-Screen([string]$file) {
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
    [System.Drawing.Graphics]::FromImage($bmp).CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
    $bmp.Save($file)
}
function Blocklist {
    $key = "$chrome\URLBlocklist"
    if (-not (Test-Path $key)) { return @() }
    $p = Get-ItemProperty $key
    @($p.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' } | ForEach-Object Value)
}
function Ctl {
    $ErrorActionPreference = 'Continue'
    $out = & $ctl @args 2>&1 | Out-String
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    Write-Host "> deepworkctl $args`n$out"
    if ($code -ne 0) { Check $false "deepworkctl $args (exit $code)" }
    $out
}

function Install([string]$exe, [string]$name) {
    $log = Join-Path $logs "$name.log"
    $p = Start-Process $exe -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/LOG=$log" -Wait -PassThru
    Write-Host "$name exit code: $($p.ExitCode)"
    $p.ExitCode
}
function Uninstall([string[]]$extra) {
    $p = Start-Process (Join-Path $dir 'unins000.exe') -ArgumentList (@('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART') + $extra) -Wait -PassThru
    # The uninstaller hands over to a copy of itself; wait for that too.
    Start-Sleep -Seconds 2
    while (Get-Process -Name '_iu*' -ErrorAction SilentlyContinue) { Start-Sleep -Milliseconds 500 }
    $p.ExitCode
}
function ServiceUp {
    for ($i = 0; $i -lt 40; $i++) {
        $s = Get-Service DeepWork -ErrorAction SilentlyContinue
        if ($s -and $s.Status -eq 'Running') {
            $ErrorActionPreference = 'Continue'
            & $ctl status *> $null
            $ok = $LASTEXITCODE -eq 0
            $ErrorActionPreference = 'Stop'
            if ($ok) { return $true }
        }
        Start-Sleep -Milliseconds 500
    }
    $false
}

Check ((Install $Setup 'install') -eq 0) 'the installer succeeds'
Check (ServiceUp) 'the service runs and answers'
$svc = Get-CimInstance Win32_Service -Filter "Name='DeepWork'"
Check ($svc.StartMode -eq 'Auto' -and $svc.StartName -eq 'LocalSystem') 'service starts with Windows, as SYSTEM'
Check ((sc.exe qfailure DeepWork | Out-String) -match 'RESTART') 'service restarts after a crash'
Check ((Get-ItemProperty $uninstallKey).DisplayVersion -eq $version) "Settings > Apps lists DeepWork $version"
Check ([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';' -contains $dir) 'deepworkctl is on the PATH'
Check ((& $ctl --version) -match [regex]::Escape($version)) 'deepworkctl --version'
foreach ($exe in 'deepwork.exe', 'deepwork-daemon.exe', 'deepworkctl.exe') {
    $info = (Get-Item (Join-Path $dir $exe)).VersionInfo
    Check ($info.ProductVersion -eq $version -and $info.ProductName -eq 'DeepWork') "$exe has version information"
}
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
Check ((Get-Content "$data\config.json" -Raw) -match [regex]::Escape($me)) 'the installing user may control DeepWork (full SID)'
Check (Test-Path (Join-Path $dir 'LICENSE')) 'license installed'
# Signed packages: every program we build, the installer and the uninstaller.
if ((Get-AuthenticodeSignature $Setup).SignerCertificate) {
    foreach ($exe in 'deepwork.exe', 'deepwork-daemon.exe', 'deepworkctl.exe', 'unins000.exe') {
        Check ([bool](Get-AuthenticodeSignature (Join-Path $dir $exe)).SignerCertificate) "$exe is signed"
    }
} else {
    Write-Host 'note: this installer is not signed'
}
Check (Test-Path (Join-Path $programs 'DeepWork.lnk')) 'Start menu shortcut'
Check ((New-Object -ComObject WScript.Shell).CreateShortcut((Join-Path $programs 'StartUp\DeepWork.lnk')).Arguments -eq '--background') 'starts in the tray at sign-in'

$out = Ctl status
Check ($out -match 'No blocks yet') 'status answers'
$out = Ctl add Test list:gambling example.com
Check ($out -match 'deepworkctl start Test') 'add suggests the name'
Ctl start Test 5 | Out-Null
Start-Sleep -Seconds 8
Check ((Get-Content $hosts -Raw) -match '0\.0\.0\.0\s+example\.com') 'hosts file blocks example.com'
Check ((Blocklist) -contains 'example.com') 'Chrome blocklist has example.com'
Check ((Get-ItemProperty $chrome).DnsOverHttpsMode -eq 'off') "Chrome's secure DNS is off"
Check ((Get-Acl $data).Owner -match 'Administrators|S-1-5-32-544') 'data folder belongs to administrators'
Check ((Get-Content "$data\deepwork.log" -Raw) -match 'service started') 'the service writes a readable log'
Check ((Get-Content "$data\state\state.json" -Raw) -match 'example.com') 'administrators can read the state'

# Apps: closed while a block is on, asked to close first if they were open
# for a while, and other programs left alone.
Write-Host "test runs in session $((Get-Process -Id $PID).SessionId)"
$apps = Join-Path $env:RUNNER_TEMP 'apps'
New-Item -ItemType Directory -Force $apps | Out-Null
foreach ($name in 'blockme', 'keepme') { Copy-Item "$env:SystemRoot\System32\PING.EXE" "$apps\$name.exe" }
function Start-Pinger([string]$name) {
    Start-Process "$apps\$name.exe" -ArgumentList '-n', '600', '127.0.0.1' -WindowStyle Hidden -PassThru
}
# A window that says in a file when it is asked to close.
$asked = Join-Path $apps 'asked.txt'
$shown = Join-Path $apps 'shown.txt'
# Not a console program: closing its console would end it without asking.
$source = Join-Path $apps 'windowed.cs'
@"
using System;
using System.IO;
using System.Windows.Forms;
static class Program {
    [STAThread]
    static void Main(string[] args) {
        var f = new Form { Text = "deepwork-e2e-window" };
        f.Shown += (s, e) => File.WriteAllText(args[0], "shown");
        f.FormClosing += (s, e) => File.WriteAllText(args[1], "asked");
        Application.Run(f);
    }
}
"@ | Set-Content $source
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "Add-Type -Path '$source' -ReferencedAssemblies System.Windows.Forms -OutputAssembly '$apps\windowed.exe' -OutputType WindowsApplication"
Check (Test-Path "$apps\windowed.exe") 'the window program is built'
function Start-Window {
    Remove-Item $shown, $asked -ErrorAction SilentlyContinue
    $p = Start-Process "$apps\windowed.exe" -ArgumentList "`"$shown`"", "`"$asked`"" -PassThru
    for ($i = 0; $i -lt 60 -and -not (Test-Path $shown); $i++) { Start-Sleep -Seconds 1 }
    Write-Host "window shown: $(Test-Path $shown), after $i s"
    $p
}
# The service's helper for asking, by itself.
$open = Start-Window
$took = Measure-Command { & "$dir\deepwork-daemon.exe" --close-windows $open.Id | Out-Host }
Write-Host "the helper took $([int]$took.TotalMilliseconds) ms"
Check ($open.WaitForExit(10000)) 'the helper closes a window'
Check (Test-Path $asked) 'it asks'
$open = Start-Window
$uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')
Write-Host "UAC: $uac, administrator: $admin"
$running = Start-Pinger 'blockme'
$keep = Start-Pinger 'keepme'
try { query session } catch { Write-Host 'query session is not available' }
Start-Sleep -Seconds 12
Check (-not $open.HasExited -and -not $running.HasExited) 'the test programs run'
$out = Ctl add Apps app:blockme app:windowed.exe
Ctl start Apps 5 | Out-Null
Check ($running.WaitForExit(20000)) 'a running program is closed'
Check ($open.WaitForExit(15000)) 'a program with a window is closed'
Check (Test-Path $asked) 'it was asked to close first'
$again = Start-Pinger 'blockme'
Check ($again.WaitForExit(5000)) 'a blocked program is closed when it starts'
Check (-not $keep.HasExited) 'another program keeps running'
Ctl stop Apps | Out-Null
$after = Start-Pinger 'blockme'
Start-Sleep -Seconds 5
Check (-not $after.HasExited) 'the program runs after the block'
Stop-Process -Id $after.Id, $keep.Id -Force

# Microsoft Defender, where the runner has it running: nothing of ours is
# flagged, and it leaves the blocks in the hosts file alone.
$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($defender -and $defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled) {
    Update-MpSignature -ErrorAction SilentlyContinue
    Start-MpScan -ScanType CustomScan -ScanPath $dir
    Start-MpScan -ScanType CustomScan -ScanPath $Setup
    $found = @(Get-MpThreatDetection -ErrorAction SilentlyContinue)
    $found | Format-List | Out-String | Write-Host
    Check ($found.Count -eq 0) 'Microsoft Defender finds nothing in DeepWork'
    Start-Sleep -Seconds 5
    Check ((Get-Content $hosts -Raw) -match '0\.0\.0\.0\s+example\.com') 'the hosts file still blocks after the scan'
} else {
    Write-Host "note: Microsoft Defender isn't running on this runner"
}

# The app, from the installed copy (MSYS2 isn't on the PATH here, so the
# bundle must be complete).
$shots = Join-Path $env:RUNNER_TEMP 'shots'
New-Item -ItemType Directory -Force $shots | Out-Null
foreach ($page in 'focus', 'blocks', 'settings') {
    $env:DEEPWORK_DEBUG_PAGE = $page
    $env:DEEPWORK_DEBUG_SHOT = Join-Path $shots "$page.png"
    $env:DEEPWORK_DEBUG_SIZE = '1000x760'
    # Run the installed copy, with MSYS2 off the PATH: the bundle must be complete.
    $log = Join-Path $shots "$page.log"
    $p = Start-Process (Join-Path $dir 'deepwork.exe') -PassThru `
        -RedirectStandardError $log -RedirectStandardOutput "$log.out"
    if (-not $p.WaitForExit(60000)) {
        Save-Screen (Join-Path $shots "desktop-$page.png")
        $p.Kill()
        Get-Content $log, "$log.out" -ErrorAction SilentlyContinue
        Check $false "the app rendered $page in time"
    }
    Get-Content $log -ErrorAction SilentlyContinue
    Check (Test-Path $env:DEEPWORK_DEBUG_SHOT) "screenshot of $page"
    # The ARM runner's session sits on Windows' first sign-in (privacy) screen,
    # where the notification area refuses icons; check it on x64 only.
    $added = (Get-Content $log -Raw) -match 'tray icon added'
    if ($env:RUNNER_ARCH -eq 'ARM64') {
        Write-Host "tray icon ($page): $(if ($added) { 'added' } else { 'not checked on this runner' })"
    } else {
        Check $added "tray icon ($page)"
    }
}
Remove-Item Env:DEEPWORK_DEBUG_PAGE, Env:DEEPWORK_DEBUG_SHOT, Env:DEEPWORK_DEBUG_SIZE

# The app picker.
$env:DEEPWORK_DEBUG_OPEN = 'apps'
$env:DEEPWORK_DEBUG_SHOT = Join-Path $shots 'apps.png'
$log = Join-Path $shots 'apps.log'
$notepad = Start-Process notepad.exe -PassThru
Start-Sleep -Seconds 3
$p = Start-Process (Join-Path $dir 'deepwork.exe') -PassThru -RedirectStandardError $log -RedirectStandardOutput "$log.out"
Check ($p.WaitForExit(60000)) 'the app picker opens'
Get-Content $log
$text = Get-Content $log -Raw
Check ($text -match 'installed apps \((\d+)\)' -and [int]$Matches[1] -ge 5) 'it lists installed apps'
if ($env:RUNNER_ARCH -ne 'ARM64') {
    Check ($text -match 'running apps \(\d+\):.*notepad') 'it lists running apps'
}
Stop-Process -Name notepad -Force -ErrorAction SilentlyContinue
Remove-Item Env:DEEPWORK_DEBUG_OPEN, Env:DEEPWORK_DEBUG_SHOT

# Frame rate with Windows' default timer and with the 1 ms timer the app asks
# for (informational: the runners have no GPU and no real display).
foreach ($mode in 'default', 'fine') {
    $env:DEEPWORK_DEBUG_FPS = '1'
    if ($mode -eq 'default') { $env:DEEPWORK_COARSE_TIMER = '1' } else { Remove-Item Env:DEEPWORK_COARSE_TIMER -ErrorAction SilentlyContinue }
    $log = Join-Path $shots "fps-$mode.log"
    $p = Start-Process (Join-Path $dir 'deepwork.exe') -PassThru -RedirectStandardError $log -RedirectStandardOutput "$log.out"
    if (-not $p.WaitForExit(60000)) { $p.Kill() }
    Write-Host "frame rate, $mode timer: $((Get-Content $log -ErrorAction SilentlyContinue | Select-String '^fps:') -join ' ')"
}
Remove-Item Env:DEEPWORK_DEBUG_FPS, Env:DEEPWORK_COARSE_TIMER -ErrorAction SilentlyContinue

# A crashed (or killed) service comes back by itself.
Stop-Process -Name deepwork-daemon -Force
Start-Sleep -Seconds 3
Check (ServiceUp) 'the service restarts after being killed'
Check (@(Get-Process deepwork-daemon).Count -eq 1) 'only one service process'

Ctl stop Test | Out-Null
Start-Sleep -Seconds 4
Check (-not ((Get-Content $hosts -Raw) -match 'example\.com')) 'hosts file is clean again'
Check (-not ((Blocklist) -contains 'example.com')) 'Chrome blocklist is clean again'
if (-not $chromeBefore) { Check (-not (Test-Path $chrome)) "Chrome's policy key is gone" }

# Updating keeps blocks and a running lock.
Ctl add Locked --lock strict example.org | Out-Null
Ctl start Locked 5 | Out-Null
Start-Sleep -Seconds 4
Check ((Install $Setup 'update') -eq 0) 'installing again (update) succeeds'
Check (ServiceUp) 'the service runs after the update'
$ErrorActionPreference = 'Continue'; & $ctl locked; $locked = $LASTEXITCODE -eq 0; $ErrorActionPreference = 'Stop'
Check $locked 'the block is still locked after the update'
Check ((Ctl status) -match 'Test') 'blocks are kept'
Start-Sleep -Seconds 4
Check ((Get-Content $hosts -Raw) -match '0\.0\.0\.0\s+example\.org') 'still blocking after the update'

# Locked: no uninstall.
Uninstall @() | Out-Null
Check (Test-Path $ctl) 'uninstall is refused while a block is locked'
Check (ServiceUp) 'the service still runs'

# Forget the locked block (the test can't wait for it), then uninstall.
sc.exe failure DeepWork reset= 0 actions= '""' | Out-Null
function Stop-DeepWork {
    for ($i = 0; $i -lt 40; $i++) {
        if ((Get-Service DeepWork).Status -eq 'Stopped') { return $true }
        sc.exe stop DeepWork | Out-Null
        Start-Sleep -Milliseconds 500
    }
    sc.exe queryex DeepWork | Write-Host
    $false
}
Check (Stop-DeepWork) 'the service stops'
Remove-Item "$data\state\state.json"
Start-Service DeepWork
Check (ServiceUp) 'the service runs without the lock'
Uninstall @('/PURGE=1') | Out-Null
Check (-not (Test-Path $ctl)) 'programs removed'
Check (-not (Test-Path $data)) 'data removed (/PURGE=1)'
Check (-not (Get-Service DeepWork -ErrorAction SilentlyContinue)) 'service removed'
Check (-not (Test-Path $uninstallKey)) 'Settings > Apps entry removed'
Check (-not (Test-Path (Join-Path $programs 'DeepWork.lnk'))) 'Start menu shortcut removed'
Check (-not (Test-Path (Join-Path $programs 'StartUp\DeepWork.lnk'))) 'sign-in shortcut removed'
Check (-not ((Get-Content $hosts -Raw) -match 'example\.(com|org)')) 'hosts file clean'
Check (-not ([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';' -contains $dir)) 'PATH cleaned'
Write-Host 'All Windows end-to-end checks passed.' -ForegroundColor Green
