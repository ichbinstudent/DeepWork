# End-to-end test of the Windows package on a CI runner (runs as administrator):
# install, block a site, check the hosts file and Chrome's policy, unblock,
# uninstall, and check that nothing is left behind.
param(
    [string]$Bin = 'target/release',
    # Folder with the bundled app (bundle-windows-app.sh); adds app checks
    # and screenshots.
    [string]$App
)
$ErrorActionPreference = 'Stop'

$pkg = Join-Path $env:RUNNER_TEMP 'deepwork-pkg'
New-Item -ItemType Directory -Force $pkg | Out-Null
Copy-Item "$Bin/deepwork-daemon.exe", "$Bin/deepworkctl.exe", windows/*.ps1, windows/*.cmd $pkg
if ($App) { Copy-Item "$App/*" $pkg -Recurse -Force }

$dir = Join-Path $env:ProgramFiles 'DeepWork'
$data = Join-Path $env:ProgramData 'DeepWork'
$ctl = Join-Path $dir 'deepworkctl.exe'
$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$chrome = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
$chromeBefore = Test-Path $chrome

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

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$pkg\install.ps1"
Check ($LASTEXITCODE -eq 0) 'install.ps1'
Check ((Get-ScheduledTask DeepWork).State -eq 'Running') 'the scheduled task runs'
Check (@(Get-ScheduledTask DeepWork).Triggers.Count -eq 2) 'start-up and watchdog triggers'
Check ([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';' -contains $dir) 'deepworkctl is on the PATH'

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

if ($App) {
    $menu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\DeepWork.lnk'
    Check (Test-Path $menu) 'Start menu shortcut'
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
    }
    Remove-Item Env:DEEPWORK_DEBUG_PAGE, Env:DEEPWORK_DEBUG_SHOT, Env:DEEPWORK_DEBUG_SIZE
}

# The watchdog trigger must not start a second copy.
Start-ScheduledTask DeepWork
Start-Sleep -Seconds 2
Check (@(Get-Process deepwork-daemon).Count -eq 1) 'only one service process'

Ctl stop Test | Out-Null
Start-Sleep -Seconds 4
Check (-not ((Get-Content $hosts -Raw) -match 'example\.com')) 'hosts file is clean again'
Check (-not ((Blocklist) -contains 'example.com')) 'Chrome blocklist is clean again'
if (-not $chromeBefore) { Check (-not (Test-Path $chrome)) "Chrome's policy key is gone" }

# Locked blocks keep the uninstaller away.
Ctl add Locked --lock strict example.org | Out-Null
Ctl start Locked 5 | Out-Null
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$pkg\uninstall.ps1"
Check ($LASTEXITCODE -ne 0) 'uninstall refuses while a block is locked'
Check (Test-Path $ctl) 'still installed'

# Forget the locked block (the test can't wait for it), then uninstall.
Stop-ScheduledTask DeepWork
Get-Process deepwork-daemon -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item "$data\state\state.json"
Start-ScheduledTask DeepWork
Start-Sleep -Seconds 3
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$pkg\uninstall.ps1" -Purge
Check ($LASTEXITCODE -eq 0) 'uninstall.ps1 -Purge'
Check (-not (Test-Path $dir)) 'programs removed'
Check (-not (Test-Path $data)) 'data removed'
Check (-not (Get-ScheduledTask DeepWork -ErrorAction SilentlyContinue)) 'scheduled task removed'
Check (-not ((Get-Content $hosts -Raw) -match 'example\.(com|org)')) 'hosts file clean'
Check (-not ([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';' -contains $dir)) 'PATH cleaned'
Write-Host 'All Windows end-to-end checks passed.' -ForegroundColor Green
