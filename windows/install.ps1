# Install DeepWork on Windows (experimental). Double-click install.cmd, or run:
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
# It asks for administrator rights when needed.
param(
    # SID of the user who may control DeepWork (default: whoever started this).
    [string]$User,
    # Wait for Enter at the end (when started in its own window).
    [switch]$Pause
)
$ErrorActionPreference = 'Stop'

function Done([int]$code) {
    if ($Pause) { Read-Host 'Press Enter to close' | Out-Null }
    exit $code
}
trap {
    Write-Host "Installing DeepWork failed: $_" -ForegroundColor Red
    Done 1
}

if (-not $User) { $User = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Run again as administrator, remembering who asked for it.
    Start-Process powershell.exe -Verb RunAs -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-User', $User, '-Pause'
    )
    exit 0
}

$dir = Join-Path $env:ProgramFiles 'DeepWork'
$data = Join-Path $env:ProgramData 'DeepWork'
$task = 'DeepWork'

Write-Host 'Stopping a running copy...'
if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $task
}
Get-Process deepwork, deepwork-daemon -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

Write-Host "Copying the programs to $dir..."
New-Item -ItemType Directory -Force $dir | Out-Null
Get-ChildItem $PSScriptRoot -Exclude '*.ps1', '*.cmd', 'README.md', 'LICENSE' |
    Copy-Item -Destination $dir -Recurse -Force
Get-ChildItem $dir -Recurse -File | Unblock-File

# Only that user (and administrators) may control the service. Users are
# identified by the last number of their SID (see: whoami /user).
New-Item -ItemType Directory -Force $data | Out-Null
$config = Join-Path $data 'config.json'
if (-not (Test-Path $config)) {
    $rid = ($User -split '-')[-1]
    Set-Content -Encoding ascii -Path $config -Value "{`r`n  `"allowed_users`": [$rid]`r`n}"
}

Write-Host 'Starting the service...'
# The service runs as SYSTEM from a scheduled task: at start-up, and every
# five minutes in case it isn't running (a running copy is left alone).
$action = New-ScheduledTaskAction -Execute (Join-Path $dir 'deepwork-daemon.exe')
$triggers = @(
    (New-ScheduledTaskTrigger -AtStartup),
    (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5))
)
$runAs = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -MultipleInstances IgnoreNew -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName $task -Action $action -Trigger $triggers `
    -Principal $runAs -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $task

# Put deepworkctl on the PATH (for terminals opened from now on).
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if (($path -split ';') -notcontains $dir) {
    [Environment]::SetEnvironmentVariable('Path', "$path;$dir", 'Machine')
}

# Start menu entry for the app, if this package has it, and its tray icon
# at sign-in (for every user).
$app = Join-Path $dir 'deepwork.exe'
if (Test-Path $app) {
    $shell = New-Object -ComObject WScript.Shell
    $programs = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
    foreach ($entry in @(
        @{ Path = (Join-Path $programs 'DeepWork.lnk'); Args = '' },
        @{ Path = (Join-Path $programs 'StartUp\DeepWork.lnk'); Args = '--background' }
    )) {
        $link = $shell.CreateShortcut($entry.Path)
        $link.TargetPath = $app
        $link.Arguments = $entry.Args
        $link.WorkingDirectory = $dir
        $link.Description = 'Block distracting websites and apps'
        $ico = Join-Path $dir 'deepwork.ico'
        if (Test-Path $ico) { $link.IconLocation = $ico }
        $link.Save()
    }
}

# Wait until the service answers.
$ctl = Join-Path $dir 'deepworkctl.exe'
$ok = $false
for ($i = 0; $i -lt 20 -and -not $ok; $i++) {
    Start-Sleep -Milliseconds 250
    $ErrorActionPreference = 'Continue'
    & $ctl status *> $null
    $ok = $LASTEXITCODE -eq 0
    $ErrorActionPreference = 'Stop'
}

Write-Host ''
if ($ok) {
    Write-Host 'DeepWork is installed and running.' -ForegroundColor Green
} else {
    Write-Host "DeepWork is installed, but the service didn't answer yet. See $data\deepwork.log" -ForegroundColor Yellow
}
if (Test-Path $app) {
    Write-Host 'Open DeepWork from the Start menu (from your next sign-in it also waits in the'
    Write-Host 'notification area), or use the command line.'
}
Write-Host 'In a new terminal:'
Write-Host '  deepworkctl lists                          built-in filter lists'
Write-Host '  deepworkctl add Social list:social         create a block'
Write-Host '  deepworkctl start Social 60                block for an hour'
Done 0
